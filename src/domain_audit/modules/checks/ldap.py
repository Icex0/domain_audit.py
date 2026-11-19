"""LDAP security checks: anonymous bind, LDAP signing and LDAPS channel binding
(the latter via NetExec)."""

import subprocess
import re
from typing import Dict
from pathlib import Path

import ldap3


from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.dc import get_domain_controllers


class LDAPChecker:
    """LDAP anonymous bind, signing and channel binding checks."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain or ldap_conn.config.domain
    
    def check_ldap(self):
        """Run all LDAP checks."""
        self._check_ldap_anonymous_bind()
        self._check_ldap_signing()
    
    def _check_ldap_anonymous_bind(self):
        """Check whether each DC allows anonymous (unauthenticated) LDAP binds."""
        self.logger.info("---Checking LDAP anonymous bind---")

        try:
            dcs = get_domain_controllers(self.ldap, ['dNSHostName', 'name'])
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
                    search_errors = []

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
                    except Exception as e:
                        search_errors.append(str(e))

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
                        except Exception as e:
                            search_errors.append(str(e))

                    if anonymous_access:
                        self.logger.finding(f"Anonymous LDAP bind allowed on {name} ({hostname})")
                        vulnerable_dcs.append(f"{name} ({hostname}): anonymous LDAP bind allowed")
                    elif len(search_errors) == 2:
                        self.logger.warning(f"[!] Could not test anonymous LDAP access on {name}: {search_errors[-1]}")
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
            dcs = get_domain_controllers(self.ldap, ['dNSHostName', 'name'])
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
                cmd = ['netexec', 'ldap', hostname, '-u', self.username] + (
                    ['-H', self.hashes] if self.hashes and not self.password else ['-p', self.password])
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
