"""Security checks module for domain_audit."""

from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from .domain import DomainChecker
from .password import PasswordChecker
from .laps import LAPSChecker
from .description import DescriptionChecker
from .roasting import RoastingChecker
from .delegation import DelegationChecker
from .user_attrs import UserAttrsChecker
from .outdated import OutdatedChecker
from .adidns import ADIDNSChecker
from .exchange import ExchangeChecker
from .adcs import ADCSChecker
from .network import NetworkChecker
from .ldap import LDAPChecker
from .trusts import TrustChecker
from .azure import AzureChecker
from .sccm import SCCMChecker
from .bloodhound import BloodHoundChecker
from .sql import SQLChecker
from .privileged_groups import PrivilegedGroupsChecker
from .smb import SMBChecker
from .access import AccessChecker
from .wsus import WSUSChecker


# Available checks registry - maps check name to (description, checker_attr, method_name)
# Ordered by execution sequence in run_all_checks()
AVAILABLE_CHECKS = {
    'bloodhound': ('BloodHound data collection', 'bloodhound_checker', 'check_bloodhound'),
    'functional-level': ('Domain functional level check', 'domain_checker', 'check_functional_level'),
    'password-policy': ('Password policy checks', 'password_checker', 'check_password_policy'),
    'kerberos-policy': ('Kerberos policy checks', 'password_checker', 'check_kerberos_policy'),
    'fgpp': ('Fine-grained password policy', 'password_checker', 'check_fine_grained_password_policy'),
    'laps': ('LAPS configuration check', 'laps_checker', 'check_laps'),
    'descriptions': ('User/computer descriptions', 'description_checker', 'check_descriptions'),
    'roasting': ('Kerberoast/AS-REP roast', 'roasting_checker', 'check_roasting'),
    'delegation': ('Delegation configuration', 'delegation_checker', 'check_delegation'),
    'user-attrs': ('User attributes check', 'user_attrs_checker', 'check_user_attributes'),
    'privileged-groups': ('Privileged groups membership', 'privileged_groups_checker', 'check_privileged_groups'),
    'outdated': ('Outdated OS/software', 'outdated_checker', 'run_all_checks'),
    'adidns': ('AD-integrated DNS', 'adidns_checker', 'check_adidns'),
    'exchange': ('Exchange configuration', 'exchange_checker', 'check_exchange'),
    'adcs': ('AD Certificate Services', 'adcs_checker', 'check_adcs'),
    'trusts': ('Domain trusts', 'trust_checker', 'check_trusts'),
    'azure': ('Azure AD Connect', 'azure_checker', 'check_azure_ad_connect'),
    'sccm': ('SCCM/MECM configuration', 'sccm_checker', 'check_sccm'),
    'ldap': ('LDAP security settings', 'ldap_checker', 'check_ldap'),
    'network': ('Network enumeration', 'network_checker', 'check_network'),
    'smb': ('SMB security checks', 'smb_checker', 'check_smb_access'),
    'access': ('Access checks (SMB/RDP/WINRM/MSSQL)', 'access_checker', 'check_access'),
    'sql': ('SQL Server enumeration', 'sql_checker', 'check_sql'),
    'wsus': ('WSUS HTTP configuration (MITM vulnerability)', 'wsus_checker', 'check_wsus'),
}


class SecurityChecker:
    """Main security checker that aggregates all check categories."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, bloodhound_options: str = "all",
                 skip_bloodhound: bool = False):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.bloodhound_options = bloodhound_options
        self.skip_bloodhound = skip_bloodhound
        
        # Initialize sub-checkers
        self.domain_checker = DomainChecker(ldap_conn, output_paths)
        self.password_checker = PasswordChecker(ldap_conn, output_paths,
                                                  server=ldap_conn.config.server,
                                                  username=username, password=password,
                                                  domain=domain)
        self.laps_checker = LAPSChecker(ldap_conn, output_paths,
                                        server=ldap_conn.config.server,
                                        username=username, password=password,
                                        domain=domain)
        self.description_checker = DescriptionChecker(ldap_conn, output_paths)
        self.roasting_checker = RoastingChecker(
            ldap_conn, output_paths,
            domain=domain, username=username, password=password,
            hashes=hashes
        )
        self.delegation_checker = DelegationChecker(ldap_conn, output_paths)
        self.user_attrs_checker = UserAttrsChecker(ldap_conn, output_paths)
        self.outdated_checker = OutdatedChecker(ldap_conn, output_paths)
        self.adidns_checker = ADIDNSChecker(ldap_conn, output_paths, domain=domain)
        self.exchange_checker = ExchangeChecker(ldap_conn, output_paths)
        self.adcs_checker = ADCSChecker(ldap_conn, output_paths,
                                         server=ldap_conn.config.server,
                                         domain=domain, username=username,
                                         password=password, hashes=hashes)
        self.network_checker = NetworkChecker(ldap_conn, output_paths, server=ldap_conn.config.server)
        self.ldap_checker = LDAPChecker(ldap_conn, output_paths, server=ldap_conn.config.server,
                                         username=username, password=password, domain=domain)
        self.trust_checker = TrustChecker(ldap_conn, output_paths)
        self.azure_checker = AzureChecker(ldap_conn, output_paths)
        self.sccm_checker = SCCMChecker(ldap_conn, output_paths)
        self.bloodhound_checker = BloodHoundChecker(ldap_conn, output_paths,
                                                     domain=domain, username=username,
                                                     password=password, hashes=hashes)
        self.sql_checker = SQLChecker(ldap_conn, output_paths,
                                       username=username, password=password, hashes=hashes)
        self.privileged_groups_checker = PrivilegedGroupsChecker(ldap_conn, output_paths)
        self.smb_checker = SMBChecker(ldap_conn, output_paths, domain=domain)
        self.access_checker = AccessChecker(ldap_conn, output_paths,
                                             domain=domain, username=username,
                                             password=password, hashes=hashes)
        self.wsus_checker = WSUSChecker(ldap_conn, output_paths,
                                         server=ldap_conn.config.server,
                                         domain=domain, username=username,
                                         password=password)
    
    def run_all_checks(self):
        """Run all Phase 4 and 5 security checks."""
        # BloodHound collection first (before any other checks)
        if not self.skip_bloodhound:
            self.bloodhound_checker.check_bloodhound(self.bloodhound_options)
        
        self.logger.section("SECURITY CHECKS - PART 1")
        
        # Domain checks
        self.domain_checker.check_functional_level()
        
        # Password policy checks
        self.password_checker.check_password_policy()
        self.password_checker.check_kerberos_policy()
        self.password_checker.check_fine_grained_password_policy()
        
        # LAPS checks
        self.laps_checker.check_laps()
        
        # Phase 5 checks
        self.logger.section("SECURITY CHECKS - PART 2")
        self.description_checker.check_descriptions()
        self.roasting_checker.check_roasting()
        self.delegation_checker.check_delegation()
        self.user_attrs_checker.check_user_attributes()
        self.privileged_groups_checker.check_privileged_groups()
        
        # Phase 6 checks
        self.logger.section("SECURITY CHECKS - PART 3")
        self.outdated_checker.run_all_checks()
        
        # Phase 7 checks
        self.logger.section("SECURITY CHECKS - PART 4")
        self.adidns_checker.check_adidns()
        self.exchange_checker.check_exchange()
        self.adcs_checker.check_adcs()
        
        # Phase 7 checks
        self.logger.section("SECURITY CHECKS - PART 5")
        self.trust_checker.check_trusts()
        self.azure_checker.check_azure_ad_connect()
        self.azure_checker.check_azure_ad_connect_server()
        self.sccm_checker.check_sccm()
        self.wsus_checker.check_wsus()
        
        # Phase 8 checks
        self.logger.section("SECURITY CHECKS - PART 6")
        self.ldap_checker.check_ldap()
        
        # Phase 9 checks
        self.logger.section("SECURITY CHECKS - PART 7")
        self.network_checker.check_network()
        
        # SMB access checks (runs after network scan identifies SMB hosts)
        self.smb_checker.check_smb_access()
        
        # Phase 12 checks
        self.logger.section("SECURITY CHECKS - PART 8")
        self.access_checker.check_access()
        self.sql_checker.check_sql()
    
    def run_check(self, check_name: str, **kwargs) -> bool:
        """Run a specific check by name.
        
        Returns True if check was found and executed, False otherwise.
        """
        if check_name not in AVAILABLE_CHECKS:
            self.logger.error(f"[-] Unknown check: {check_name}")
            return False
        
        description, checker_attr, method_name = AVAILABLE_CHECKS[check_name]
        checker = getattr(self, checker_attr, None)
        
        if not checker:
            self.logger.error(f"[-] Checker not initialized: {checker_attr}")
            return False
        
        method = getattr(checker, method_name, None)
        if not method:
            self.logger.error(f"[-] Method not found: {method_name}")
            return False
        
        self.logger.info(f"Running check: {check_name} - {description}")
        
        # Special handling for bloodhound which needs options
        if check_name == 'bloodhound':
            method(kwargs.get('bloodhound_options', 'all'))
        else:
            method()
        
        return True
    
    @staticmethod
    def list_checks() -> Dict[str, str]:
        """Return dict of available check names and descriptions."""
        return {name: info[0] for name, info in AVAILABLE_CHECKS.items()}


__all__ = [
    'SecurityChecker',
    'DomainChecker', 'PasswordChecker', 'LAPSChecker',
    'DescriptionChecker', 'RoastingChecker', 'DelegationChecker', 'UserAttrsChecker',
    'OutdatedChecker', 'ADIDNSChecker', 'ExchangeChecker', 'ADCSChecker',
    'NetworkChecker', 'LDAPChecker', 'TrustChecker', 'AzureChecker', 'SCCMChecker',
    'BloodHoundChecker', 'SQLChecker', 'PrivilegedGroupsChecker', 'SMBChecker',
    'AccessChecker', 'WSUSChecker'
]
