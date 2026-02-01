"""LDAP and SYSVOL security checks.

Uses netexec to check LDAP signing and channel binding.
"""

import subprocess
import re
from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
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
        self._check_ldap_signing()
        self._check_sysvol_passwords()
        self._check_netlogon_passwords()
        self._check_printspooler_dc()
    
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
        
        for dc in dcs:
            hostname = dc.get('dNSHostName', '')
            name = dc.get('name', '')
            
            if not hostname:
                continue
            
            self.logger.info(f"[*] Checking DC: {name} ({hostname})")
            
            try:
                result = subprocess.run(
                    ['netexec', 'ldap', hostname, '-u', self.username, '-p', self.password],
                    capture_output=True,
                    text=True,
                    timeout=60
                )
                
                # Debug: raw netexec output
                self.logger.debug(f"netexec ldap stdout:\n{result.stdout}")
                self.logger.debug(f"netexec ldap stderr:\n{result.stderr}")
                
                output = result.stdout + result.stderr
                
                # Parse the banner line for signing and channel binding
                # Example: (signing:None) (channel binding:Never)
                signing_match = re.search(r'\(signing:(\w+)\)', output)
                binding_match = re.search(r'\(channel binding:(\w+)\)', output)
                
                signing = signing_match.group(1) if signing_match else None
                binding = binding_match.group(1) if binding_match else None
                
                results = [f"Domain Controller: {name} ({hostname})"]
                
                # Check LDAP signing
                if signing:
                    if signing.lower() == 'true':
                        self.logger.success(f"[+] {name}: LDAP signing IS enforced")
                        results.append("LDAP signing: ENFORCED")
                    else:
                        self.logger.finding(f"[-] {name}: LDAP signing NOT enforced")
                        results.append("LDAP signing: NOT ENFORCED")
                        vulnerable_dcs.append(f"{name}: LDAP signing not enforced")
                else:
                    self.logger.warning(f"[!] {name}: Could not determine LDAP signing")
                    results.append("LDAP signing: UNKNOWN")
                
                # Check LDAPS channel binding
                if binding:
                    if binding.lower() == 'required':
                        self.logger.success(f"[+] {name}: LDAPS channel binding REQUIRED")
                        results.append("LDAPS channel binding: REQUIRED")
                    elif binding.lower() == 'never':
                        self.logger.finding(f"[-] {name}: LDAPS channel binding NEVER - relay attacks possible")
                        results.append("LDAPS channel binding: NEVER (vulnerable to relay)")
                        vulnerable_dcs.append(f"{name}: LDAPS channel binding set to Never")
                    elif binding.lower() in ('supported', 'when_supported'):
                        self.logger.warning(f"[!] {name}: LDAPS channel binding WHEN SUPPORTED")
                        results.append("LDAPS channel binding: WHEN SUPPORTED")
                    else:
                        self.logger.info(f"[*] {name}: LDAPS channel binding: {binding}")
                        results.append(f"LDAPS channel binding: {binding}")
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
                self.logger.error(f"[-] Error checking {name}: {e}")
        
        # Write results
        if all_results:
            write_lines(all_results, self.output_paths['data'] / 'ldap_checks.txt')
        
        # Write findings if vulnerable
        if vulnerable_dcs:
            write_lines(vulnerable_dcs, self.output_paths['findings'] / 'ldap_vulnerabilities.txt')
    
    def _check_sysvol_passwords(self):
        """Check for passwords in SYSVOL share using impacket."""
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
            
            findings = []
            
            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')
                
                if not hostname:
                    continue
                
                self.logger.info(f"[*] Checking SYSVOL of {name}")
                
                try:
                    conn = SMBConnection(hostname, hostname)
                    conn.login(self.username, self.password, self.domain)
                    
                    # Connect to SYSVOL share
                    conn.connectTree('SYSVOL')
                    
                    # Search for XML files with password patterns
                    domain_folder = f"{self.domain}"
                    policies_path = f"{domain_folder}/Policies"
                    
                    found_password = False
                    
                    try:
                        # List policies folders
                        files = conn.listPath('SYSVOL', policies_path + "/*")
                        
                        for file in files:
                            if file.is_directory() and file.get_longname() not in ['.', '..']:
                                policy_path = f"{policies_path}/{file.get_longname()}"
                                try:
                                    policy_files = conn.listPath('SYSVOL', policy_path + "/*")
                                    
                                    for pf in policy_files:
                                        fname = pf.get_longname()
                                        if fname.endswith('.xml'):
                                            file_path = f"{policy_path}/{fname}"
                                            try:
                                                # Read file content
                                                tid = conn.connectTree('SYSVOL')
                                                fid = conn.openFile(tid, file_path)
                                                content = conn.readFile(tid, fid)
                                                conn.closeFile(tid, fid)
                                                
                                                if content:
                                                    content_lower = content.lower()
                                                    for keyword in SYSVOL_PASSWORD_KEYWORDS:
                                                        if keyword.encode() in content_lower:
                                                            found_password = True
                                                            findings.append(f"{name}: Found '{keyword}' in {file_path}")
                                                            break
                                                    
                                            except Exception as e:
                                                self.logger.debug(f"Error reading {file_path}: {e}")
                                                
                                except Exception as e:
                                    self.logger.debug(f"Error listing {policy_path}: {e}")
                                    
                    except Exception as e:
                        self.logger.debug(f"Error listing SYSVOL policies: {e}")
                    
                    conn.logoff()
                    
                    if found_password:
                        self.logger.warning(f"[!] Possible passwords found in SYSVOL of {name}")
                    else:
                        self.logger.success(f"[+] No obvious passwords in SYSVOL of {name}")
                        
                except Exception as e:
                    self.logger.error(f"[-] Error accessing SYSVOL on {hostname}: {e}")
            
            if findings:
                write_lines(findings,
                           self.output_paths['checks'] / 'sysvol_passwords.txt')
                self.logger.warning("[!] Please manually check SYSVOL for passwords")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking SYSVOL: {e}")
    
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
        """Check if PrintSpooler service is running on DCs using rpcdump."""
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
            
            for dc in dcs:
                hostname = dc.get('dNSHostName', '')
                name = dc.get('name', '')
                
                if not hostname:
                    continue
                
                try:
                    # Use impacket's rpcdump.py to check for MS-RPRN or MS-PAR
                    result = subprocess.run(
                        ['rpcdump.py', hostname],
                        capture_output=True,
                        text=True,
                        timeout=30
                    )
                    
                    # Debug: raw rpcdump output
                    self.logger.debug(f"rpcdump stdout:\n{result.stdout}")
                    self.logger.debug(f"rpcdump stderr:\n{result.stderr}")
                    
                    output = result.stdout + result.stderr
                    
                    # Check for Print Spooler RPC interfaces
                    if 'MS-RPRN' in output or 'MS-PAR' in output:
                        self.logger.finding(f"PrintSpooler enabled on {name}")
                        spooler_enabled.append(f"{name} ({hostname})")
                        spooler_enabled.append(output)
                        spooler_enabled.append("")
                    else:
                        self.logger.success(f"[+] PrintSpooler disabled on {name}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.warning(f"[!] Timeout checking {hostname}")
                except FileNotFoundError:
                    self.logger.error("[-] impacket rpcdump not available")
                    break
                except Exception as e:
                    self.logger.debug(f"Error checking {hostname}: {e}")
            
            if spooler_enabled:
                write_lines(spooler_enabled,
                           self.output_paths['findings'] / 'printspooler_domaincontrollers.txt')
                self.logger.finding("PrintSpooler enabled on one or more DCs - PetitPotam attack possible")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking PrintSpooler: {e}")
