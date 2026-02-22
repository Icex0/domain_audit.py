"""SMB access checks - null authentication, guest access, and domain admin sessions."""

import subprocess
import tempfile
import os
import re
import csv
from typing import Dict, List, Set
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines


class SMBChecker:
    """Check SMB hosts for null authentication, guest access, and domain admin sessions."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
    
    def check_smb_access(self, smb_hosts: List[str] = None):
        """Run SMB access checks on discovered hosts.
        
        Args:
            smb_hosts: List of IP addresses with SMB (port 445) open.
                      If None, reads from scandata_hostalive_smb.txt
        """
        # Load SMB hosts from file if not provided
        if smb_hosts is None:
            smb_hosts = self._load_smb_hosts()
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check for access")
            return
        
        self._check_null_session(smb_hosts)
        self._check_guest_access(smb_hosts)
    
    def _load_smb_hosts(self) -> List[str]:
        """Load SMB hosts from scan data file."""
        smb_file = self.output_paths['data'] / 'scandata_hostalive_smb.txt'
        if smb_file.exists():
            with open(smb_file, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        return []
    
    def _check_null_session(self, smb_hosts: List[str]):
        """Check for null/anonymous session access on SMB hosts using netexec."""
        self.logger.info("---Checking for SMB null session access---")
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check")
            return
        
        try:
            # Create temp file with SMB host IPs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for ip in smb_hosts:
                    f.write(f"{ip}\n")
                hosts_file = f.name
            
            self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for null session")
            
            # Run netexec with null credentials (empty username and password)
            # netexec smb <targets> -u '' -p ''
            cmd = ['netexec', 'smb', hosts_file, '-u', '', '-p', '']
            
            self.logger.debug(f"[*] Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=900  # 15 minute timeout for larger networks
            )
            
            output = (result.stdout or '') + (result.stderr or '')
            
            # Debug: raw netexec output (only with -v flag)
            self.logger.debug(f"netexec null session stdout:\n{result.stdout}")
            self.logger.debug(f"netexec null session stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_null_session.txt')
            
            # Parse for successful null sessions
            # Look for lines with [+] indicating success or "STATUS_ACCESS_DENIED" for failures
            null_session_hosts = []
            
            for line in output.split('\n'):
                # netexec shows [+] for success, [-] for failure
                # Success pattern: SMB  10.0.0.1  445  HOSTNAME  [+] \: 
                if '[+]' in line and 'SMB' in line:
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        null_session_hosts.append(ip_match.group())
            
            null_session_hosts = sorted(set(null_session_hosts))
            
            if null_session_hosts:
                self.logger.finding(f"{len(null_session_hosts)} hosts allow SMB null session")
                write_lines(null_session_hosts,
                           self.output_paths['findings'] / 'smb_null_session.txt')
            else:
                self.logger.success("[+] No hosts allow SMB null session")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec null session check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking null session: {e}")
        finally:
            try:
                os.unlink(hosts_file)
            except Exception:
                pass
    
    def _check_guest_access(self, smb_hosts: List[str]):
        """Check for guest account access on SMB hosts using netexec."""
        self.logger.info("---Checking for SMB guest access---")
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check")
            return
        
        try:
            # Create temp file with SMB host IPs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for ip in smb_hosts:
                    f.write(f"{ip}\n")
                hosts_file = f.name
            
            self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for guest access")
            
            # Run netexec with guest credentials
            # netexec smb <targets> -u 'guest' -p ''
            cmd = ['netexec', 'smb', hosts_file, '-u', 'guest', '-p', '']
            
            self.logger.debug(f"[*] Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=900  # 15 minute timeout for larger networks
            )
            
            output = (result.stdout or '') + (result.stderr or '')
            
            # Debug: raw netexec output (only with -v flag)
            self.logger.debug(f"netexec guest access stdout:\n{result.stdout}")
            self.logger.debug(f"netexec guest access stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_guest_access.txt')
            
            # Parse for successful guest access
            guest_access_hosts = []
            
            for line in output.split('\n'):
                # Look for [+] indicating successful authentication
                # Also check for "(Guest)" which netexec shows when guest session is established
                if '[+]' in line and 'SMB' in line:
                    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', line)
                    if ip_match:
                        guest_access_hosts.append(ip_match.group())
            
            guest_access_hosts = sorted(set(guest_access_hosts))
            
            if guest_access_hosts:
                self.logger.finding(f"{len(guest_access_hosts)} hosts allow SMB guest access")
                write_lines(guest_access_hosts,
                           self.output_paths['findings'] / 'smb_guest_access.txt')
            else:
                self.logger.success("[+] No hosts allow SMB guest access")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec guest access check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking guest access: {e}")
        finally:
            try:
                os.unlink(hosts_file)
            except Exception:
                pass
    
    def _load_domain_admins(self) -> List[str]:
        """Load domain admins from data file."""
        admins_file = self.output_paths['data'] / 'list_domainadmins.txt'
        if admins_file.exists():
            with open(admins_file, 'r') as f:
                return [line.strip().lower() for line in f if line.strip()]
        return []
    
    def _load_domain_controllers(self) -> Set[str]:
        """Load domain controller hostnames from data file."""
        dc_file = self.output_paths['data'] / 'data_domaincontrollers.csv'
        dc_hostnames = set()
        
        if dc_file.exists():
            with open(dc_file, 'r', newline='') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if 'sAMAccountName' in row and row['sAMAccountName']:
                        # Remove trailing $ from computer account name
                        hostname = row['sAMAccountName'].rstrip('$').upper()
                        dc_hostnames.add(hostname)
                    if 'dNSHostName' in row and row['dNSHostName']:
                        # Also add the DNS hostname (without domain suffix)
                        dns_name = row['dNSHostName'].split('.')[0].upper()
                        dc_hostnames.add(dns_name)
        
        return dc_hostnames
    
    def check_domain_admin_sessions(self, smb_hosts: List[str] = None):
        """Check for domain admin sessions on non-domain controller systems.
        
        This is a security finding because domain admin credentials should only
        be used on domain controllers to prevent credential theft.
        
        Args:
            smb_hosts: List of IP addresses with SMB (port 445) open.
                      If None, reads from scandata_hostalive_smb.txt
        """
        self.logger.info("---Checking for domain admin sessions on non-DCs---")
        
        # Verify we have credentials
        if not self.username:
            self.logger.info("[*] No credentials available, skipping domain admin sessions check")
            return
        
        # Load SMB hosts from file if not provided
        if smb_hosts is None:
            smb_hosts = self._load_smb_hosts()
        
        if not smb_hosts:
            self.logger.info("[*] No SMB hosts to check for domain admin sessions")
            return
        
        # Load domain admins
        domain_admins = self._load_domain_admins()
        if not domain_admins:
            self.logger.info("[*] No domain admins list found, skipping session check")
            return
        
        # Load domain controllers to exclude from findings
        dc_hostnames = self._load_domain_controllers()
        self.logger.debug(f"[*] Loaded {len(dc_hostnames)} domain controller hostnames")
        
        hosts_file = None
        admins_file = None
        
        try:
            # Create temp file with SMB host IPs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for ip in smb_hosts:
                    f.write(f"{ip}\n")
                hosts_file = f.name
            
            # Create temp file with domain admin usernames
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for admin in domain_admins:
                    f.write(f"{admin}\n")
                admins_file = f.name
            
            self.logger.info(f"[*] Checking {len(smb_hosts)} SMB hosts for domain admin sessions")
            
            # Build command: netexec smb <hosts> -u <user> -p <pass> --reg-sessions <admins>
            cmd = ['netexec', 'smb', hosts_file, '-u', self.username]
            
            if self.hashes and not self.password:
                cmd.extend(['-H', self.hashes])
            else:
                cmd.extend(['-p', self.password if self.password else ''])
            
            cmd.extend(['--reg-sessions', admins_file])
            
            self.logger.debug(f"[*] Running: {' '.join(cmd)}")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=900  # 15 minute timeout for larger networks
            )
            
            output = (result.stdout or '') + (result.stderr or '')
            
            # Strip ANSI color codes
            output = re.sub(r'\x1b\[[0-9;]*m', '', output)
            
            # Debug: raw netexec output
            self.logger.debug(f"netexec reg-sessions stdout:\n{result.stdout}")
            self.logger.debug(f"netexec reg-sessions stderr:\n{result.stderr}")
            
            # Write raw output for reference
            write_lines(output.split('\n'),
                       self.output_paths['data'] / 'netexec_reg_sessions.txt')
            
            # Parse output for domain admin sessions on non-DCs
            # Output format: SMB  IP  445  HOSTNAME  username  SID
            # Lines with SID (S-1-5-21) indicate a session was found
            findings = []
            seen = set()
            
            for line in output.split('\n'):
                # Look for lines containing SID pattern (indicates session data)
                if 'S-1-5-21' not in line:
                    continue
                
                # Skip header lines
                if 'USERNAME' in line or '========' in line:
                    continue
                
                # Parse the line to extract hostname, IP, and username
                # Format: SMB  10.2.10.13  445  SCCM-SQL  ludus\domainadmin  S-1-5-21-...
                parts = line.split()
                if len(parts) < 5:
                    continue
                
                # Find IP (second field), hostname (after port 445), and username (before SID)
                ip = None
                hostname = None
                username = None
                
                for i, part in enumerate(parts):
                    if part == 'SMB' and i + 1 < len(parts):
                        # IP is the field after "SMB"
                        ip = parts[i + 1]
                    if part == '445' and i + 1 < len(parts):
                        hostname = parts[i + 1]
                    if 'S-1-5-21' in part and i > 0:
                        username = parts[i - 1]
                        break
                
                if not hostname or not username or not ip:
                    continue
                
                # Normalize hostname for comparison
                hostname_upper = hostname.upper()
                
                # Skip if this is a domain controller
                if hostname_upper in dc_hostnames:
                    self.logger.debug(f"[*] Skipping DC: {hostname}")
                    continue
                
                # Extract just the username (remove domain prefix if present)
                if '\\' in username:
                    username = username.split('\\')[1]
                
                # Check if this user is in domain admins list
                if username.lower() not in domain_admins:
                    continue
                
                # Create finding entry: "username - hostname (ip)"
                finding_key = f"{username.lower()} {hostname_upper}"
                if finding_key not in seen:
                    seen.add(finding_key)
                    findings.append(f"{username} - {hostname} ({ip})")
            
            # Sort findings by hostname (second field)
            findings = sorted(findings, key=lambda x: x.split()[1] if len(x.split()) > 1 else x)
            
            if findings:
                self.logger.finding(f"{len(findings)} domain admin sessions on non-DCs")
                write_lines(findings,
                           self.output_paths['findings'] / 'domainadmin_sessions_nondcs.txt')
            else:
                self.logger.success("[+] No domain admin sessions on non-DCs")
                
        except subprocess.TimeoutExpired:
            self.logger.error("[-] netexec reg-sessions check timed out")
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
        except Exception as e:
            self.logger.error(f"[-] Error checking domain admin sessions: {e}")
        finally:
            # Clean up temp files
            for f in [hosts_file, admins_file]:
                if f:
                    try:
                        os.unlink(f)
                    except Exception:
                        pass
