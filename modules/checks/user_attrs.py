"""User attribute security checks."""

from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_lines


class UserAttrsChecker:
    """Checks for user attributes that decrease account security."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_user_attributes(self):
        """Run all user attribute-related checks."""
        self._check_passwd_not_reqd()
        self._check_dont_expire_password()
        self._check_reversible_encryption()
        self._check_des_encryption()
    
    def _check_passwd_not_reqd(self):
        """Check for users with PASSWD_NOTREQD attribute."""
        self.logger.info("---Checking PASSWD_NOTREQD users---")
        
        try:
            # PASSWD_NOTREQD = 0x20 = 32
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=32)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_passwdnotreqd.txt'
            
            if users:
                count = len(users)
                self.logger.finding(f"{count} users have PASSWD_NOTREQD (password not required)")
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                write_lines(names, filepath)
                self.logger.info("[+] These users may have empty passwords - consider testing")
            else:
                self.logger.success("[+] No users with PASSWD_NOTREQD")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking PASSWD_NOTREQD: {e}")
    
    def _check_dont_expire_password(self):
        """Check for users with DONT_EXPIRE_PASSWORD attribute."""
        self.logger.info("---Checking DONT_EXPIRE_PASSWORD users---")
        
        try:
            # DONT_EXPIRE_PASSWORD = 0x10000 = 65536
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_dontexpirepassword.txt'
            
            if users:
                count = len(users)
                self.logger.finding(f"{count} users have DONT_EXPIRE_PASSWORD flag")
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with DONT_EXPIRE_PASSWORD flag")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking DONT_EXPIRE_PASSWORD: {e}")
    
    def _check_reversible_encryption(self):
        """Check for users with reversible encryption enabled."""
        self.logger.info("---Checking reversible encryption users---")
        
        try:
            # ENCRYPTED_TEXT_PWD_ALLOWED = 0x80 = 128
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=128))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_reversibleencryption.txt'
            
            if users:
                count = len(users)
                self.logger.finding(f"{count} users have reversible encryption (CRITICAL!)")
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with reversible encryption")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking reversible encryption: {e}")
    
    def _check_des_encryption(self):
        """Check for users with DES encryption only."""
        self.logger.info("---Checking DES encryption users---")
        
        try:
            # USE_DES_KEY_ONLY = 0x200000 = 2097152
            users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2097152))',
                attributes=['sAMAccountName', 'userAccountControl']
            )
            
            filepath = self.output_paths['findings'] / 'users_desencryption.txt'
            
            if users:
                count = len(users)
                self.logger.finding(f"{count} users have DES-only encryption (WEAK!)")
                names = [u.get('sAMAccountName', '') for u in users if u.get('sAMAccountName')]
                write_lines(names, filepath)
            else:
                self.logger.success("[+] No users with DES-only encryption")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking DES encryption: {e}")
