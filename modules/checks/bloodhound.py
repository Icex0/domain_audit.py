"""BloodHound integration using netexec (BloodHound CE format)."""

import subprocess
import zipfile
from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines


class BloodHoundChecker:
    """BloodHound data collection wrapper."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes
    
    def check_bloodhound(self, collection_method: str = "all", zip_output: bool = True):
        """Run BloodHound data collection.
        
        Args:
            collection_method: all, default, sessions, acl, or computer
            zip_output: Whether to create a ZIP archive of the output
        """
        self.logger.info("---Checking BloodHound data collection---")
        
        # Check if netexec is available
        try:
            result = subprocess.run(
                ['netexec', '--help'],
                capture_output=True,
                timeout=10
            )
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self.logger.error("[-] netexec not found. Install: pip install netexec")
            return False
        
        # Get DC to query
        dc = self.ldap.config.server
        
        # Create BloodHound output directory
        bh_output = self.output_paths['data'] / 'bloodhound'
        bh_output.mkdir(parents=True, exist_ok=True)
        
        self.logger.info(f"[*] Running BloodHound collection: {collection_method}")
        self.logger.info(f"[*] Output directory: {bh_output}")
        
        # Build netexec command with --bloodhound flag
        cmd = [
            'netexec', 'ldap', dc,
            '-u', self.username,
            '-p', self.password,
            '--bloodhound',
            '-c', collection_method
        ]
        
        # Use hashes if provided instead of password
        if self.hashes and not self.password:
            cmd = [
                'netexec', 'ldap', dc,
                '-u', self.username,
                '-H', self.hashes,
                '--bloodhound',
                '-c', collection_method
            ]
        
        try:
            self.logger.info(f"[*] Starting BloodHound collection (this may take a while)...")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 minute timeout
                cwd=str(bh_output)  # Set working directory to bloodhound folder
            )
            
            output = result.stdout + result.stderr
            
            if result.returncode == 0:
                self.logger.success("[+] BloodHound collection completed successfully")
                
                # Parse output to find netexec's ZIP file path
                zip_source = None
                for line in output.split('\n'):
                    if 'Compressing output into' in line:
                        zip_source = line.split('Compressing output into')[-1].strip()
                        break
                    elif '_bloodhound.zip' in line:
                        # Fallback: extract any line containing the zip path
                        parts = line.split()
                        for part in parts:
                            if '_bloodhound.zip' in part:
                                zip_source = part
                                break
                
                if zip_source and Path(zip_source).exists():
                    # Copy netexec's ZIP to our bloodhound folder
                    import shutil
                    zip_dest = bh_output / 'bloodhound.zip'
                    shutil.copy2(zip_source, zip_dest)
                    self.logger.info(f"[*] BloodHound ZIP saved to: {zip_dest}")
                else:
                    self.logger.warning("[!] Could not locate netexec's BloodHound ZIP file")
                    if zip_source:
                        self.logger.debug(f"Expected path: {zip_source}")
                
                # Save output log
                write_lines(
                    ["BloodHound Collection Output", "=" * 40, "", output],
                    bh_output / 'bloodhound_output.txt'
                )
                
                return True
            else:
                self.logger.error(f"[-] BloodHound collection failed with code {result.returncode}")
                self.logger.debug(f"Error output: {output}")
                return False
                
        except subprocess.TimeoutExpired:
            self.logger.warning("[!] BloodHound collection timed out after 5 minutes")
            return False
        except Exception as e:
            self.logger.error(f"[-] Error running BloodHound: {e}")
            return False
    
    def check_bloodhound_all(self):
        """Run full BloodHound collection."""
        return self.check_bloodhound(collection_method="all")
    
    def check_bloodhound_default(self):
        """Run default BloodHound collection (faster, less data)."""
        return self.check_bloodhound(collection_method="default")
    
    def check_bloodhound_sessions(self):
        """Collect session data only."""
        return self.check_bloodhound(collection_method="sessions")
    
    def check_bloodhound_acl(self):
        """Collect ACL data only."""
        return self.check_bloodhound(collection_method="acl")
