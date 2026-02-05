"""SMB access checks - null authentication and guest access."""

import subprocess
import tempfile
import os
import re
from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines


class SMBChecker:
    """Check SMB hosts for null authentication and guest access."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
    
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
            result = subprocess.run(
                ['netexec', 'smb', hosts_file, '-u', '', '-p', ''],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout + result.stderr
            
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
            result = subprocess.run(
                ['netexec', 'smb', hosts_file, '-u', 'guest', '-p', ''],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = result.stdout + result.stderr
            
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
