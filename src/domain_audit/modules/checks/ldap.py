"""LDAP and SYSVOL security checks.

Uses netexec to check LDAP signing and channel binding.
"""

import io
import subprocess
import re
from typing import Dict, List
from pathlib import Path

import ldap3

from impacket.dcerpc.v5 import transport, rprn

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.gpp import find_cpasswords, find_autologon
from ...utils.dc import select_reachable_dc
from ...config import SYSVOL_PASSWORD_KEYWORDS, NETLOGON_PASSWORD_KEYWORDS


class LDAPChecker:
    """LDAP signing, channel binding, and SYSVOL checks."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain
    
    def check_ldap(self):
        """Run all LDAP and SYSVOL checks."""
        self._check_ldap_anonymous_bind()
        self._check_ldap_signing()
        self._check_sysvol_passwords()
        self._check_netlogon_passwords()
        self._check_printspooler_dc()
    
    def _check_ldap_anonymous_bind(self):
        """Check whether each DC allows anonymous (unauthenticated) LDAP binds."""
        self.logger.info("---Checking LDAP anonymous bind---")

        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
        except Exception as e:
            self.logger.error(f"[-] Failed to query domain controllers: {e}")
            dcs = []

        if not dcs:
            dcs = [{'dNSHostName': self.server, 'name': 'DC'}]

        vulnerable_dcs = []

        for dc in dcs:
            hostname = dc.get('dNSHostName', '')
            name = dc.get('name', '')

            if not hostname:
                continue

            self.logger.info(f"[*] Testing anonymous LDAP bind on {name} ({hostname})")

            try:
                server = ldap3.Server(hostname, port=389, get_info=ldap3.NONE)
                conn = ldap3.Connection(
                    server,
                    authentication=ldap3.ANONYMOUS,
                    auto_bind=ldap3.AUTO_BIND_NONE,
                    receive_timeout=10
                )
                bound = conn.bind()

                if bound:
                    # Windows AD always accepts an anonymous bind, so we must
                    # verify whether the server actually allows querying
                    # domain data.  rootDSE is always accessible anonymously
                    # (RFC 4512), so we skip it and test real domain queries.
                    anonymous_access = False

                    # Try to read an actual domain object
                    try:
                        conn.search(
                            search_base=self.base_dn,
                            search_filter='(objectClass=domain)',
                            search_scope=ldap3.BASE,
                            attributes=['distinguishedName']
                        )
                        # ldap3 does not raise on operationsError, so check
                        # the result code explicitly (0 = success)
                        if conn.result.get('result') == 0 and conn.entries:
                            anonymous_access = True
                    except Exception:
                        pass

                    # Fallback: try enumerating users (single result)
                    if not anonymous_access:
                        try:
                            conn.search(
                                search_base=self.base_dn,
                                search_filter='(objectClass=user)',
                                search_scope=ldap3.SUBTREE,
                                attributes=['sAMAccountName'],
                                size_limit=1
                            )
                            if conn.result.get('result') == 0 and conn.entries:
                                anonymous_access = True
                        except Exception:
                            pass

                    if anonymous_access:
                        self.logger.finding(f"Anonymous LDAP bind allowed on {name} ({hostname})")
                        vulnerable_dcs.append(f"{name} ({hostname}): anonymous LDAP bind allowed")
                    else:
                        self.logger.success(f"[+] Anonymous LDAP bind denied on {name}")

                else:
                    self.logger.success(f"[+] Anonymous LDAP bind denied on {name}")

                conn.unbind()

            except Exception as e:
                self.logger.debug(f"Anonymous bind check failed for {hostname}: {e}")
                self.logger.warning(f"[!] Could not test anonymous bind on {name}: {e}")

        if vulnerable_dcs:
            write_lines(vulnerable_dcs,
                        self.output_paths['findings'] / 'ldap_anonymous_bind.txt')

    def _check_ldap_signing(self):
        """Check LDAP signing and LDAPS channel binding using netexec."""
        self.logger.info("---Checking LDAP signing and LDAPS channel binding---")
        
        # Get all domain controllers
        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
        except Exception as e:
            self.logger.error(f"[-] Failed to query domain controllers: {e}")
            dcs = []
        
        if not dcs:
            self.logger.warning("[!] No domain controllers found, trying configured server")
            dcs = [{'dNSHostName': self.server, 'name': 'DC'}]
        
        all_results = []
        vulnerable_dcs = []
        completed_checks = 0
        
        for dc in dcs:
            hostname = dc.get('dNSHostName', '')
            name = dc.get('name', '')
            
            if not hostname:
                continue
            
            self.logger.info(f"[*] Checking DC: {name} ({hostname})")
            
            try:
                cmd = ['netexec', 'ldap', hostname, '-u', self.username, '-p', self.password]
                # Avoid exposing credentials in debug logs.
                self.logger.debug(f"[*] Running netexec ldap against {hostname}")
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=60
                )
                
                # Debug: raw netexec output
                self.logger.debug(f"netexec ldap stdout:\n{result.stdout}")
                self.logger.debug(f"netexec ldap stderr:\n{result.stderr}")
                
                output = (result.stdout or '') + (result.stderr or '')
                
                # Parse the banner line for signing and channel binding
                # Example: (signing:None) (channel binding:Never)
                signing_match = re.search(r'\(signing:\s*([^)]+)\)', output, re.I)
                binding_match = re.search(r'\(channel binding:\s*([^)]+)\)', output, re.I)
                
                # NetExec uses Enforced/None/Unknown for signing and
                # Always/When Supported/Never/No TLS cert for channel binding.
                signing = signing_match.group(1).strip().lower() if signing_match else None
                binding = binding_match.group(1).strip().lower() if binding_match else None

                results = [f"Domain Controller: {name} ({hostname})"]
                if signing in ('enforced', 'true', 'none', 'false'):
                    completed_checks += 1

                # Only report a vulnerability for an explicitly insecure state.
                if signing in ('enforced', 'true'):
                    self.logger.success(f"[+] {name}: LDAP signing IS enforced")
                    results.append("LDAP signing: ENFORCED")
                elif signing in ('none', 'false'):
                    self.logger.finding(f"{name}: LDAP signing NOT enforced")
                    results.append("LDAP signing: NOT ENFORCED")
                    vulnerable_dcs.append(f"{name}: LDAP signing not enforced")
                else:
                    self.logger.warning(f"[!] {name}: Could not determine LDAP signing")
                    results.append("LDAP signing: UNKNOWN")

                if binding in ('always', 'required'):
                    self.logger.success(f"[+] {name}: LDAPS channel binding REQUIRED")
                    results.append("LDAPS channel binding: REQUIRED")
                elif binding == 'never':
                    self.logger.finding(f"{name}: LDAPS channel binding NEVER - relay attacks possible")
                    results.append("LDAPS channel binding: NEVER (vulnerable to relay)")
                    vulnerable_dcs.append(f"{name}: LDAPS channel binding set to Never")
                elif binding in ('when supported', 'when_supported', 'supported'):
                    self.logger.warning(f"[!] {name}: LDAPS channel binding WHEN SUPPORTED")
                    results.append("LDAPS channel binding: WHEN SUPPORTED")
                elif binding == 'no tls cert':
                    self.logger.warning(f"[!] {name}: LDAPS channel binding could not be tested (No TLS cert)")
                    results.append("LDAPS channel binding: UNKNOWN (No TLS cert)")
                else:
                    self.logger.warning(f"[!] {name}: Could not determine LDAPS channel binding")
                    results.append("LDAPS channel binding: UNKNOWN")
                
                all_results.extend(results)
                all_results.append("")
                
                # Also save raw output
                all_results.append("Raw netexec output:")
                all_results.extend(output.strip().split('\n'))
                all_results.append("")
                    
            except subprocess.TimeoutExpired:
                self.logger.error(f"[-] Timeout checking {hostname}")
            except FileNotFoundError:
                self.logger.error("[-] netexec not found")
                break
            except Exception as e:
                self.logger.error(f"Error checking {name}: {e}")
        
        # Write results
        if all_results:
            write_lines(all_results, self.output_paths['data'] / 'ldap_checks.txt')
        
        # Remove outdated results from an earlier run only when all DCs
        # returned a recognizable signing status.
        findings_path = self.output_paths['findings'] / 'ldap_vulnerabilities.txt'
        if vulnerable_dcs:
            write_lines(vulnerable_dcs, findings_path)
        elif completed_checks == len(dcs) and completed_checks > 0:
            findings_path.unlink(missing_ok=True)
    
    def _check_sysvol_passwords(self):
        """Check SYSVOL GPO folders for GPP cpasswords and password keywords.

        Group Policy Preferences XML files sit several levels deep, e.g.
        Policies/{GUID}/Machine/Preferences/Groups/Groups.xml, so the Policies
        folder is walked recursively. SYSVOL is replicated between DCs, so one
        reachable DC is scanned.
        """
        self.logger.info("---Checking SYSVOL for passwords---")
        self.logger.info("[*] This might take a while")
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available")
            return
        
        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            if not dcs:
                self.logger.info("[*] No domain controllers found")
                return
            hostname = select_reachable_dc(dcs, fallback=self.server, logger=self.logger)
            
            conn = SMBConnection(hostname, hostname)
            conn.login(self.username, self.password, self.domain)
            
            gpp_findings = []
            autologon_findings = []
            keyword_hits = []
            xml_count = 0
            for file_path in self._walk_share(conn, 'SYSVOL', f"{self.domain}/Policies"):
                if not file_path.lower().endswith('.xml'):
                    continue
                xml_count += 1
                content = self._read_share_file(conn, 'SYSVOL', file_path)
                if not content:
                    continue
                
                found_credentials = False
                for entry in find_cpasswords(content):
                    password = entry['password'] or f"<could not decrypt: {entry['cpassword']}>"
                    gpp_findings.append(f"{file_path}: user '{entry['user'] or '?'}' password '{password}'")
                    found_credentials = True
                if file_path.lower().endswith('registry.xml'):
                    for entry in find_autologon(content):
                        user = f"{entry['domain']}\\{entry['user']}" if entry['domain'] else (entry['user'] or '?')
                        autologon_findings.append(f"{file_path}: autologon user '{user}' password '{entry['password']}'")
                        found_credentials = True
                if found_credentials:
                    continue  # already reported with the actual credentials; skip the keyword hit
                
                content_lower = content.lower()
                for keyword in SYSVOL_PASSWORD_KEYWORDS:
                    if keyword.encode() in content_lower:
                        keyword_hits.append(f"Found '{keyword}' in {file_path}")
                        break
            
            conn.logoff()
            self.logger.info(f"[*] Scanned {xml_count} XML files in SYSVOL of {hostname}")
            
            if gpp_findings:
                self.logger.finding(f"{len(gpp_findings)} Group Policy Preferences passwords (cpassword) found in SYSVOL")
                write_lines(gpp_findings, self.output_paths['findings'] / 'sysvol_gpp_passwords.txt')
            else:
                self.logger.success("[+] No Group Policy Preferences passwords (cpassword) found in SYSVOL")
            
            if autologon_findings:
                self.logger.finding(f"{len(autologon_findings)} cleartext autologon password(s) in Group Policy Preferences (Registry.xml)")
                write_lines(autologon_findings, self.output_paths['findings'] / 'sysvol_gpp_autologon.txt')
            else:
                self.logger.success("[+] No Group Policy Preferences autologon passwords found in SYSVOL")
            
            if keyword_hits:
                self.logger.warning(f"[!] {len(keyword_hits)} SYSVOL XML files contain password keywords - please check manually")
                write_lines(keyword_hits, self.output_paths['checks'] / 'sysvol_passwords.txt')
                
        except Exception as e:
            self.logger.error(f"[-] Error checking SYSVOL: {e}")
    
    def _walk_share(self, conn, share: str, path: str, depth: int = 0, max_depth: int = 12):
        """Recursively yield file paths below path on an SMB share."""
        if depth > max_depth:
            return
        try:
            entries = conn.listPath(share, f"{path}/*")
        except Exception as e:
            self.logger.debug(f"Error listing {share}/{path}: {e}")
            return
        for entry in entries:
            name = entry.get_longname()
            if name in ('.', '..'):
                continue
            full_path = f"{path}/{name}"
            if entry.is_directory():
                yield from self._walk_share(conn, share, full_path, depth + 1, max_depth)
            else:
                yield full_path
    
    def _read_share_file(self, conn, share: str, path: str, max_size: int = 10 * 1024 * 1024) -> bytes:
        """Read a file from an SMB share, returning b'' on error or if too large."""
        buffer = io.BytesIO()
        try:
            def write(data):
                if buffer.tell() + len(data) > max_size:
                    raise ValueError("file too large")
                buffer.write(data)
            conn.getFile(share, path, write)
            return buffer.getvalue()
        except Exception as e:
            self.logger.debug(f"Error reading {share}/{path}: {e}")
            return b''
    
    def _check_netlogon_passwords(self):
        """Check for passwords in NETLOGON share using impacket."""
        self.logger.info("---Checking NETLOGON for passwords---")
        self.logger.info("[*] This might take a while")
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available")
            return
        
        try:
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not dcs:
                self.logger.info("[*] No domain controllers found")
                return
            
            findings = []
            
            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')
                
                if not hostname:
                    continue
                
                self.logger.info(f"[*] Checking NETLOGON of {name}")
                
                try:
                    conn = SMBConnection(hostname, hostname)
                    conn.login(self.username, self.password, self.domain)
                    
                    # Connect to NETLOGON share
                    conn.connectTree('NETLOGON')
                    
                    # List files recursively and check content
                    found_password = False
                    
                    def scan_share_path(conn, share, path=""):
                        nonlocal found_password
                        try:
                            files = conn.listPath(share, path + "/*" if path else "*")
                            
                            for file in files:
                                fname = file.get_longname()
                                if fname in ['.', '..']:
                                    continue
                                    
                                full_path = f"{path}/{fname}" if path else fname
                                
                                if file.is_directory():
                                    scan_share_path(conn, share, full_path)
                                else:
                                    # Check filename for any keyword
                                    fname_lower = fname.lower()
                                    for keyword in NETLOGON_PASSWORD_KEYWORDS:
                                        if keyword in fname_lower:
                                            found_password = True
                                            findings.append(f"{name}: Suspicious filename '{full_path}' (matched '{keyword}')")
                                            break
                                    
                                    # Try to read text files
                                    if fname.endswith(('.bat', '.cmd', '.ps1', '.vbs', '.txt')):
                                        try:
                                            tid = conn.connectTree(share)
                                            fid = conn.openFile(tid, full_path)
                                            content = conn.readFile(tid, fid)
                                            conn.closeFile(tid, fid)
                                            
                                            if content:
                                                content_lower = content.lower()
                                                for keyword in NETLOGON_PASSWORD_KEYWORDS:
                                                    if keyword.encode() in content_lower:
                                                        found_password = True
                                                        findings.append(f"{name}: Found '{keyword}' in {full_path}")
                                                        break
                                                
                                        except Exception as e:
                                            self.logger.debug(f"Error reading {full_path}: {e}")
                        except Exception as e:
                            self.logger.debug(f"Error listing {path}: {e}")
                    
                    scan_share_path(conn, 'NETLOGON')
                    conn.logoff()
                    
                    if found_password:
                        self.logger.warning(f"[!] Possible passwords found in NETLOGON of {name}")
                    else:
                        self.logger.success(f"[+] No obvious passwords in NETLOGON of {name}")
                        
                except Exception as e:
                    self.logger.error(f"[-] Error accessing NETLOGON on {hostname}: {e}")
            
            if findings:
                write_lines(findings,
                           self.output_paths['checks'] / 'netlogon_passwords.txt')
                self.logger.warning("[!] Please manually check NETLOGON for passwords")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking NETLOGON: {e}")
    
    def _check_printspooler_dc(self):
        """Check if PrintSpooler service is running on DCs using impacket RPC."""
        self.logger.info("---Checking PrintSpooler service on DCs---")
        
        try:
            # Get domain controllers
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not dcs:
                self.logger.info("[*] No domain controllers found")
                return
            
            spooler_enabled = []
            spooler_unknown = []

            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')

                if not hostname:
                    continue

                # Check for MS-RPRN (Print Spooler) using impacket
                status, detail = self._check_spooler_rpc(hostname)
                if status is True:
                    self.logger.finding(f"PrintSpooler enabled on {name}")
                    spooler_enabled.append(f"{name} ({hostname})")
                elif status is False:
                    self.logger.success(f"[+] PrintSpooler disabled on {name}")
                else:
                    self.logger.warning(f"[!] PrintSpooler status unknown on {name}: {detail}")
                    spooler_unknown.append(f"{name} ({hostname}): {detail}")

            if spooler_enabled:
                write_lines(spooler_enabled,
                           self.output_paths['findings'] / 'printspooler_domaincontrollers.txt')
            if spooler_unknown:
                write_lines(spooler_unknown,
                           self.output_paths['checks'] / 'printspooler_domaincontrollers_unknown.txt')
                                           
        except Exception as e:
            self.logger.error(f"[-] Error checking PrintSpooler: {e}")
    
    def _check_spooler_rpc(self, target: str):
        """Check if the Print Spooler RPC interface is available on target.

        Returns (status, detail): status is True (running), False (not running:
        the \\pipe\\spoolss named pipe doesn't exist) or None (unknown, e.g.
        authentication failure, access denied or timeout).
        """
        try:
            # MS-RPRN UUID (Print System Remote Protocol)
            MSRPRN_UUID = ('12345678-1234-abcd-ef00-0123456789ab', '1.0')
            
            # Try to bind to the MS-RPRN interface
            string_binding = f'ncacn_np:{target}[\\pipe\\spoolss]'
            rpc_transport = transport.DCERPCTransportFactory(string_binding)
            
            # Set credentials if available
            if self.username and self.password:
                rpc_transport.set_credentials(self.username, self.password, self.domain, '', '')
            
            rpc_transport.set_connect_timeout(10)
            
            dce = rpc_transport.get_dce_rpc()
            dce.connect()
            dce.bind(rprn.MSRPC_UUID_RPRN)
            
            # If we get here, spooler is running
            dce.disconnect()
            return True, ''

        except Exception as e:
            self.logger.debug(f"Spooler check failed for {target}: {e}")
            # A stopped spooler removes the spoolss pipe, so opening it fails with
            # STATUS_OBJECT_NAME_NOT_FOUND. Any other error doesn't tell us the state.
            if 'STATUS_OBJECT_NAME_NOT_FOUND' in str(e):
                return False, ''
            return None, str(e) or type(e).__name__
