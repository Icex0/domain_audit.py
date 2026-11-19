"""Check which non-admin principals can log on to domain controllers over RDP.

The RDP logon right on a DC is "Allow log on through Remote Desktop Services"
(SeRemoteInteractiveLogonRight) minus "Deny log on through Remote Desktop
Services" (SeDenyRemoteInteractiveLogonRight). Microsoft's effective default on
DCs is Administrators only; Remote Desktop Users only get it on member servers
and workstations. How the effective value is determined (LSA when permitted,
otherwise GPO / default) is in utils.user_rights.
"""

import socket
from pathlib import Path
from typing import Dict, List

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.user_rights import DCUserRights
from ...utils.dc import get_domain_controllers

ALLOW_RIGHT = 'SeRemoteInteractiveLogonRight'
DENY_RIGHT = 'SeDenyRemoteInteractiveLogonRight'
DEFAULT_DC_RDP_SIDS = {'S-1-5-32-544'}  # Administrators
RDP_USERS_SID = 'S-1-5-32-555'          # Remote Desktop Users


class DCRDPChecker:
    """Reports non-admin principals that are allowed to RDP to domain controllers."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.rights = DCUserRights(ldap_conn, self.logger, domain, username, password, hashes)

    def check_dc_rdp(self):
        self.logger.info("---Checking which non-admins can log on to domain controllers over RDP---")
        try:
            dcs = get_domain_controllers(self.ldap)
        except Exception as e:
            self.logger.error(f"[-] Could not list domain controllers: {e}")
            return
        if not dcs:
            self.logger.info("[*] No domain controllers found")
            return

        findings: List[str] = []
        verify: List[str] = []
        for dc in dcs:
            name = dc.get('sAMAccountName', '').rstrip('$') or dc['distinguishedName']
            host = dc.get('dNSHostName') or self.ldap.config.server
            port_note = '' if self._port_open(host, 3389) else ' (port 3389 not reachable from here)'

            result = self.rights.holders(dc, ALLOW_RIGHT, DENY_RIGHT, DEFAULT_DC_RDP_SIDS)
            if result.error:
                self.logger.warning(f"[!] {name}: RDP logon right could not be determined - {result.error}")
                verify.append(f"{name}: RDP logon right could not be determined ({result.error})")
                continue

            principals = self.rights.non_admin_principals(result.sids)
            if principals:
                findings.append(f"{name}{port_note} - source: {result.source}")
                findings.extend(f"  {p}" for p in principals)
            elif not result.certain:
                rdu = self.rights.non_admin_principals({RDP_USERS_SID})
                note = f"; Remote Desktop Users has non-admin members ({rdu[0].split(' - ', 1)[-1]})" if rdu else ''
                verify.append(f"{name}: no non-admin RDP logon right via {result.source}, but local policy can't be read "
                              f"with these credentials (run as admin for effective rights){note}")

        if findings:
            self.logger.finding("Non-admin principals can log on to domain controllers over RDP")
            write_lines(findings, self.output_paths['findings'] / 'dc_rdp_access.txt')
        else:
            self.logger.success("[+] No non-admin principals with the RDP logon right on domain controllers found")
        if verify:
            self.logger.warning(f"[!] RDP logon rights on {len(verify)} DC(s) need manual verification")
            write_lines(verify, self.output_paths['checks'] / 'dc_rdp_access_verify.txt')

    @staticmethod
    def _port_open(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False
