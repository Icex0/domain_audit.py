"""LDAP connection and query utilities."""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass

from ldap3 import Server, Connection, NTLM, SUBTREE, ALL_ATTRIBUTES
from ldap3.core.exceptions import LDAPBindError, LDAPSocketOpenError, LDAPException

from ..utils.logger import get_logger
from ..core.exceptions import ConnectionError, EnumerationError


@dataclass
class LDAPConfig:
    """LDAP connection configuration."""
    server: str
    domain: str
    username: str
    password: str
    use_ldaps: bool = False
    use_kerberos: bool = False
    
    @property
    def domain_username(self) -> str:
        """Return DOMAIN\\username format."""
        return f"{self.domain.upper()}\\{self.username}"
    
    @property
    def base_dn(self) -> str:
        """Generate base DN from domain."""
        return ','.join([f"DC={part}" for part in self.domain.lower().split('.')])


class LDAPConnection:
    """Manages LDAP connections and queries."""
    
    def __init__(self, config: LDAPConfig):
        self.config = config
        self.connection: Optional[Connection] = None
        self.logger = get_logger()
    
    def connect(self) -> bool:
        """Establish LDAP connection."""
        try:
            port = 636 if self.config.use_ldaps else 389
            server = Server(
                self.config.server,
                port=port,
                use_ssl=self.config.use_ldaps,
                get_info='ALL'
            )
            
            self.connection = Connection(
                server,
                user=self.config.domain_username,
                password=self.config.password,
                authentication=NTLM,
                auto_bind=True,
                raise_exceptions=True
            )
            
            self.logger.log_verbose(f"Connected to LDAP server {self.config.server}")
            return True
            
        except (LDAPBindError, LDAPSocketOpenError) as e:
            self.logger.error(f"LDAP connection failed: {e}")
            raise ConnectionError(f"Failed to connect to LDAP: {e}")
        except Exception as e:
            self.logger.error(f"LDAP error: {e}")
            raise ConnectionError(f"LDAP error: {e}")
    
    def disconnect(self):
        """Close LDAP connection."""
        if self.connection:
            try:
                self.connection.unbind()
                self.logger.log_verbose("LDAP connection closed")
            except:
                pass
    
    def query(self, search_base: str, search_filter: str, attributes: List[str] = None) -> List[Dict]:
        """
        Execute LDAP query.
        
        Args:
            search_base: Base DN for search
            search_filter: LDAP filter string
            attributes: List of attributes to retrieve (default: ALL)
            
        Returns:
            List of dictionaries with entry data
        """
        if not self.connection:
            raise ConnectionError("LDAP not connected")
        
        try:
            attrs = attributes if attributes else ALL_ATTRIBUTES
            
            self.connection.search(
                search_base=search_base,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=attrs
            )
            
            results = []
            for entry in self.connection.entries:
                entry_data = {}
                for attr in entry.entry_attributes:
                    value = entry[attr].value
                    if isinstance(value, list) and len(value) == 1:
                        value = value[0]
                    entry_data[attr] = value
                results.append(entry_data)
            
            return results
            
        except LDAPException as e:
            self.logger.error(f"LDAP query failed: {e}")
            raise EnumerationError(f"Query failed: {e}")
    
    def get_config_dn(self) -> str:
        """Get the Configuration naming context from RootDSE."""
        if not self.connection:
            raise ConnectionError("LDAP not connected")
        
        try:
            # Query RootDSE - attributes are returned in allOperationalAttributes
            self.connection.search(
                search_base='',
                search_filter='(objectClass=*)',
                search_scope=0,  # BASE scope for RootDSE
                attributes=['*', '+']  # All user + operational attributes
            )
            
            if self.connection.entries:
                entry = self.connection.entries[0]
                # RootDSE attributes are stored in entry entry_attributes
                for attr in entry.entry_attributes:
                    if attr.lower() == 'configurationnamingcontext':
                        value = entry[attr].value
                        if isinstance(value, list):
                            return value[0]
                        return value
            
            raise EnumerationError("Could not retrieve Configuration naming context")
            
        except LDAPException as e:
            self.logger.error(f"Failed to get Configuration DN: {e}")
            raise EnumerationError(f"Failed to get Configuration DN: {e}")
    
    def get_domain_sid(self) -> str:
        """Get the domain SID."""
        results = self.query(
            search_base=self.config.base_dn,
            search_filter='(objectClass=domain)',
            attributes=['objectSid']
        )
        
        if not results:
            raise EnumerationError("Could not retrieve domain SID")
        
        sid_bytes = results[0].get('objectSid')
        if isinstance(sid_bytes, list):
            sid_bytes = sid_bytes[0]
        
        return self._convert_sid(sid_bytes)
    
    @staticmethod
    def _convert_sid(sid_bytes) -> str:
        """Convert binary SID to string format."""
        if isinstance(sid_bytes, str):
            return sid_bytes
        
        # Parse binary SID
        revision = sid_bytes[0]
        sub_authority_count = sid_bytes[1]
        identifier_authority = int.from_bytes(sid_bytes[2:8], 'big')
        
        sid_str = f"S-{revision}-{identifier_authority}"
        
        offset = 8
        for i in range(sub_authority_count):
            sub_authority = int.from_bytes(sid_bytes[offset:offset+4], 'little')
            sid_str += f"-{sub_authority}"
            offset += 4
        
        return sid_str
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()
