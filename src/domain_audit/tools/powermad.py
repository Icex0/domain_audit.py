"""ADIDNS enumeration functions based on Powermad.

Implements ADIDNS enumeration and permission checking based on Powermad.ps1
by Kevin Robertson (@kevin_robertson).

Reference: https://github.com/Kevin-Robertson/Powermad
"""

import ldap3
from typing import Optional


class ADIDNSEnumerator:
    """ADIDNS enumeration and permission checking."""
    
    def __init__(self, ldap_conn, domain: str, server: str):
        self.ldap = ldap_conn
        self.domain = domain
        self.server = server
        self.domain_parts = domain.split('.')
    
    def _build_dn(self, zone: str, partition: str = "DomainDNSZones", node: Optional[str] = None) -> str:
        """Build distinguished name for ADIDNS zone/node."""
        # Build the base path for the partition
        if partition == "System":
            base = f"CN={partition}"
        else:
            base = f"DC={partition}"
        
        # Add domain components to base
        for dc in self.domain_parts:
            base += f",DC={dc}"
        
        # Build the DNS path
        if node:
            dns_path = f"DC={node},DC={zone},CN=MicrosoftDNS,{base}"
        else:
            dns_path = f"DC={zone},CN=MicrosoftDNS,{base}"
        
        return dns_path
    

    

    def check_wildcard_record(self, zone: Optional[str] = None,
                              partition: str = "DomainDNSZones") -> Optional[bool]:
        """Check if a wildcard ('*') node exists in an ADIDNS zone.
        
        Returns:
            True if it exists, False if not, None if the lookup failed
        """
        dn = self._build_dn(zone or self.domain, partition, '*')
        try:
            return bool(self.ldap.query_raw(dn, '(objectClass=*)', ['dnsRecord'], scope=ldap3.BASE))
        except Exception as e:
            self.ldap.logger.debug(f"Wildcard lookup in {partition} failed: {e}")
            return None
    
