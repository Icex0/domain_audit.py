"""Active Directory authentication and credential management."""

import sys
from dataclasses import dataclass
from typing import Optional, Tuple

from impacket.smbconnection import SMBConnection
from impacket.krb5.kerberosv5 import KerberosError
from ldap3 import Server, Connection, NTLM, AUTO_BIND_NONE
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError

from ..utils.logger import get_logger
from .exceptions import ConnectionError

import socket


def check_dc_reachable(dc_ip: str, ports: list = [389, 636, 445, 88]) -> bool:
    """Check if the domain controller is reachable on common AD ports."""
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((dc_ip, port))
            sock.close()
            if result == 0:
                return True
        except Exception:
            continue
    return False


@dataclass
class Credentials:
    """Credential container."""
    domain: str
    username: str
    password: str
    lm_hash: Optional[str] = None
    nt_hash: Optional[str] = None
    use_kerberos: bool = False
    use_ldaps: bool = False
    
    @property
    def domain_username(self) -> str:
        """Return DOMAIN\\username format."""
        return f"{self.domain.upper()}\\{self.username}"
    
    @property
    def user_principal_name(self) -> str:
        """Return user@domain format."""
        return f"{self.username}@{self.domain.lower()}"
    
    def has_ntlm_hash(self) -> bool:
        """Check if NTLM hash is provided."""
        return self.nt_hash is not None


class ADAuthManager:
    """Manages AD authentication and connections."""
    
    def __init__(self, credentials: Credentials, dc_ip: str):
        self.creds = credentials
        self.dc_ip = dc_ip
        self.ldap_connection: Optional[Connection] = None
        self.smb_connection: Optional[SMBConnection] = None
        self.authenticated = False
        self.logger = get_logger()
    
    def test_authentication(self) -> bool:
        """
        Test authentication against the domain controller.
        
        Returns:
            True if authentication succeeds, False otherwise
        """
        try:
            self.logger.log_verbose(f"Testing credentials {self.creds.domain_username} against {self.dc_ip}")
            
            # First check if DC is reachable
            self.logger.log_verbose(f"Checking if {self.dc_ip} is reachable...")
            if not check_dc_reachable(self.dc_ip):
                self.logger.error(f"[-] Domain Controller {self.dc_ip} is not reachable")
                self.logger.error("[-] Please verify the DC IP/hostname is correct and accessible")
                return False
            self.logger.log_verbose(f"{self.dc_ip} is reachable, attempting authentication...")
            
            # Try LDAP bind first
            if self._test_ldap_auth():
                self.authenticated = True
                self.logger.success(f"[+] AD Authentication for {self.creds.domain_username} succeeded!")
                return True
            
            # Fallback to SMB
            if self._test_smb_auth():
                self.authenticated = True
                self.logger.success(f"[+] AD Authentication for {self.creds.domain_username} succeeded!")
                return True
            
            self.logger.error(f"[-] AD Authentication for {self.creds.domain_username} failed")
            return False
            
        except Exception as e:
            self.logger.error(f"[-] AD Authentication for {self.creds.domain_username} failed: {e}")
            return False
    
    def _test_ldap_auth(self) -> bool:
        """Test authentication via LDAP bind."""
        try:
            port = 636 if self.creds.use_ldaps else 389
            server = Server(self.dc_ip, port=port, use_ssl=self.creds.use_ldaps, get_info='ALL')
            
            if self.creds.has_ntlm_hash():
                # Pass-the-hash authentication
                from impacket.ldap import ldap
                # Use LDAP with NTLM and hash
                conn = Connection(
                    server,
                    user=self.creds.domain_username,
                    password=self.creds.nt_hash,
                    authentication=NTLM,
                    auto_bind=AUTO_BIND_NONE
                )
            else:
                # Password authentication
                conn = Connection(
                    server,
                    user=self.creds.domain_username,
                    password=self.creds.password,
                    authentication=NTLM,
                    auto_bind=AUTO_BIND_NONE
                )
            
            if conn.bind():
                self.ldap_connection = conn
                return True
            return False
            
        except (LDAPBindError, LDAPSocketOpenError) as e:
            self.logger.log_verbose(f"LDAP auth failed: {e}")
            return False
        except Exception as e:
            self.logger.log_verbose(f"LDAP auth error: {e}")
            return False
    
    def _test_smb_auth(self) -> bool:
        """Test authentication via SMB."""
        try:
            smb = SMBConnection(self.dc_ip, self.dc_ip)
            
            if self.creds.has_ntlm_hash():
                # Pass-the-hash
                lm_hash = self.creds.lm_hash if self.creds.lm_hash else ''
                smb.login(
                    self.creds.username,
                    self.creds.password,
                    self.creds.domain,
                    lmhash=lm_hash,
                    nthash=self.creds.nt_hash
                )
            else:
                # Password login
                smb.login(self.creds.username, self.creds.password, self.creds.domain)
            
            if smb.isLoginRequired():
                self.smb_connection = smb
                return True
            return False
            
        except Exception as e:
            self.logger.log_verbose(f"SMB auth failed: {e}")
            return False
    

    
    def close(self):
        """Close all connections."""
        if self.ldap_connection:
            try:
                self.ldap_connection.unbind()
            except:
                pass
        
        if self.smb_connection:
            try:
                self.smb_connection.close()
            except:
                pass



