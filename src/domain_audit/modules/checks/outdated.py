"""Phase 6 security checks - Outdated computers, inactive objects, privileged objects, domain join, Pre-Windows 2000."""

from typing import Dict
from pathlib import Path


from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from .stale import StaleObjectsMixin
from .privileged_accounts import PrivilegedAccountsMixin
from .legacy import LegacyAccessMixin


class OutdatedChecker(StaleObjectsMixin, PrivilegedAccountsMixin, LegacyAccessMixin):
    """Checks for outdated operating systems and inactive objects. (the checks live in stale.py, privileged_accounts.py and legacy.py)"""

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

    def run_all_checks(self):
        """Run all Phase 6 checks."""
        self._check_outdated_computers()
        self._check_inactive_objects()
        self._check_privileged_objects()
        self._check_privileged_old_passwords()
        self._check_krbtgt_password()
        self._check_domain_join()
        self._check_prewindows2000_group()
        self._check_anonymous_logon_groups()
        self._check_prewindows2000_computers()

    def check_privileged_accounts(self):
        """Privileged account hardening: Protected Users / delegation flags,
        privileged password age, and KRBTGT password age."""
        self._check_privileged_objects()
        self._check_privileged_old_passwords()
        self._check_krbtgt_password()

    def check_legacy(self):
        """Legacy access & misconfiguration: Pre-Windows 2000 group/computers,
        anonymous logon group membership, and who can join machines to the domain."""
        self._check_prewindows2000_group()
        self._check_prewindows2000_computers()
        self._check_anonymous_logon_groups()
        self._check_domain_join()
