"""Active Directory Certificate Services (ADCS) security checks."""

from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv


class ADCSChecker:
    """Checks for Active Directory Certificate Services configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_adcs(self):
        """Run all ADCS security checks."""
        self._check_cert_publishers()
    
    def _check_cert_publishers(self):
        """Check for ADCS by searching for PKI Enrollment Services."""
        self.logger.info("---Checking if Active Directory Certificate Services is used within the domain---")
        
        try:
            # Get Configuration naming context (pKIEnrollmentService is stored there)
            config_dn = self.ldap.get_config_dn()
            
            enrollment_services = self.ldap.query(
                search_base=config_dn,
                search_filter='(objectClass=pKIEnrollmentService)',
                attributes=['cn', 'dNSHostName', 'cACertificateDN']
            )
            
            if not enrollment_services:
                self.logger.success("[+] ADCS not found (no PKI Enrollment Services)")
                return
            
            results = []
            for service in enrollment_services:
                # Get PKI Enrollment Server (dNSHostName)
                dns_hostname = service.get('dNSHostName', '')
                if dns_hostname:
                    self.logger.warning(f"[!] Found PKI Enrollment Server: {dns_hostname}")
                
                # Get CA Common Name
                ca_cn = service.get('cn', '')
                if ca_cn:
                    self.logger.warning(f"[!] Found CN: {ca_cn}")
                
                results.append({
                    'type': 'PKI Enrollment Service',
                    'cn': ca_cn,
                    'dns_hostname': dns_hostname
                })
            
            if results:
                self.logger.warning(f"[!] ADCS installed with {len(results)} PKI Enrollment Service(s)")
                write_csv(results, self.output_paths['checks'] / 'ADCS.txt')
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ADCS: {e}")
