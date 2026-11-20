"""System Center Operations Manager (SCOM) detection.

Same LDAP queries as scomhunter: SCOM management servers register the
MSOMHSvc (Health Service) SPN, and the SDK / Data Access service runs under a
domain account with an MSOMSdkSvc SPN (kerberoastable). SCOM itself is not a
vulnerability, but its Run As accounts and agent configuration are a known
attack path (SpecterOps, "SCOMmand and Conquer", Dec 2025).
"""

from pathlib import Path
from typing import Dict, List

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines

USER_ACCOUNT_TYPE = 805306368  # SAM_NORMAL_USER_ACCOUNT


def _as_list(value) -> List:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class SCOMChecker:
    """Detects SCOM management servers and SDK service accounts."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn

    def check_scom(self):
        self.logger.info("---Checking for SCOM (System Center Operations Manager)---")
        try:
            servers = self.ldap.query(self.base_dn, '(servicePrincipalName=MSOMHSvc/*)',
                                      ['dNSHostName', 'sAMAccountName', 'servicePrincipalName'])
            accounts = self.ldap.query(
                self.base_dn,
                f'(&(servicePrincipalName=MSOMSdkSvc/*)(sAMAccountType={USER_ACCOUNT_TYPE}))',
                ['sAMAccountName', 'description', 'servicePrincipalName'])
        except Exception as e:
            self.logger.error(f"[-] Error checking for SCOM: {e}")
            return

        if not servers and not accounts:
            self.logger.success("[+] SCOM not found (no MSOMHSvc/MSOMSdkSvc SPNs)")
            return

        lines = ["SCOM (System Center Operations Manager) found in the domain.", ""]
        if servers:
            lines.append("Management servers (MSOMHSvc SPN):")
            for s in servers:
                lines.append(f"  - {s.get('dNSHostName') or s.get('sAMAccountName')}")
            lines.append("")
        if accounts:
            lines.append("SDK / Data Access service accounts (MSOMSdkSvc SPN, kerberoastable):")
            for a in accounts:
                desc = a.get('description')
                lines.append(f"  - {a.get('sAMAccountName')}" + (f" ({desc})" if desc else ''))
            lines.append("")
        lines += [
            "SCOM Run As accounts are often privileged and can be recovered from management servers",
            "and agents; review the SCOM attack paths, e.g. with scomhunter:",
            "  scomhunter find -u <user> -p <password> -d <domain> -dc-ip <DC IP>",
            "  https://specterops.io/blog/2025/12/10/scommand-and-conquer-attacking-system-center-operations-manager-part-1",
        ]
        names = [str(s.get('dNSHostName') or s.get('sAMAccountName')) for s in servers]
        self.logger.warning(f"[!] SCOM in use: {len(servers)} management server(s)"
                            + (f" ({', '.join(names)})" if names else '')
                            + (f", {len(accounts)} SDK service account(s)" if accounts else '')
                            + " - review attack paths")
        write_lines(lines, self.output_paths['checks'] / 'SCOM.txt')
