"""LLMNR check: is multicast name resolution disabled by GPO, per computer.

GPO setting: Computer Configuration > Administrative Templates > Network >
DNS Client > Turn off multicast name resolution
(HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient\\EnableMulticast = 0).
NBT-NS is configured per network adapter (DHCP option / local registry) and
can't be checked from GPOs.
"""

from pathlib import Path
from typing import Dict

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file
from ...utils.sysvol import SysvolClient, has_credentials
from ...utils.gpo_scope import GPOScope
from .ntlm import gpo_dword_settings


class LLMNRChecker:
    """Evaluate the effective LLMNR (EnableMulticast) GPO setting per computer."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None,
                 username: str = None, password: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes

    def check_llmnr(self):
        self.logger.info("---Checking LLMNR configuration---")
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning("[!] LLMNR check requires SMB credentials")
            return

        try:
            sysvol = SysvolClient.shared(self.ldap, self.domain, self.username, self.password, self.hashes, self.logger)
            scope = GPOScope(self.ldap, self.logger)
            linked = scope.linked_gpo_guids()
            guids = [g for g in sysvol.gpo_folders() if not linked or g.upper() in linked]
            values = {guid: cfg['enable_multicast'] for guid, cfg in
                      gpo_dword_settings(sysvol, guids, {'enablemulticast': 'enable_multicast'}, key_contains='dnsclient').items()}
            names = {guid: (scope.gpos[guid].name if guid in scope.gpos else guid) for guid in values}

            if not any(v == 0 for v in values.values()):
                self.logger.warning("[!] No domain GPO disables LLMNR - vulnerable to Responder unless disabled via local GPO/registry/MDM (verify on host)")
                self._write_not_disabled()
                return

            # A GPO only disables LLMNR where it's linked, not blocked, not
            # security/WMI-filtered and not overridden - evaluate per computer.
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'distinguishedName', 'objectSid', 'primaryGroupID', 'userAccountControl']
            )
            results = {c.get('sAMAccountName', c['distinguishedName']): scope.effective_value(c, values) for c in computers}
        except Exception as e:
            self.logger.error(f"[-] Error checking LLMNR: {e}")
            return

        disabled = sorted(n for n, r in results.items() if r.status == 'configured' and r.value == 0)
        enabled = sorted(n for n, r in results.items()
                         if r.status == 'not_configured' or (r.status == 'configured' and r.value != 0))
        unclear = sorted((n, r) for n, r in results.items() if r.status in ('conflict', 'uncertain'))

        gpo_lines = [f"  {names[g]}: EnableMulticast = {v} ({'disabled' if v == 0 else 'enabled'})" for g, v in values.items()]
        summary = [
            "LLMNR Configuration (effective per computer)", "=" * 50, "",
            "GPOs setting EnableMulticast:", *gpo_lines, "",
            f"LLMNR disabled by GPO: {len(disabled)} computers",
            f"LLMNR not disabled:    {len(enabled)} computers",
            f"Needs verification:    {len(unclear)} computers",
        ]
        write_file('\n'.join(summary + ["", "Disabled on:"] + [f"  {n}" for n in disabled]),
                   self.output_paths['checks'] / 'llmnr_disabled.txt', self.logger)

        if enabled:
            self.logger.finding(f"LLMNR is not disabled by GPO on {len(enabled)} of {len(results)} enabled computers")
            write_file('\n'.join(summary + ["", "LLMNR not disabled on (GPO not linked/applied, or EnableMulticast=1):"] +
                                 [f"  {n}" for n in enabled]),
                       self.output_paths['findings'] / 'llmnr_enabled.txt', self.logger)
        else:
            self.logger.success(f"[+] LLMNR is disabled via GPO on all {len(disabled)} computers that could be evaluated")

        if unclear:
            self.logger.warning(f"[!] LLMNR GPO scope couldn't be determined for {len(unclear)} computers - verify manually")
            write_file('\n'.join([f"{n}: {r.status} - {r.reason} ({', '.join(r.gpos)})" for n, r in unclear]),
                       self.output_paths['checks'] / 'llmnr_verify.txt', self.logger)

    def _write_not_disabled(self):
        output_lines = [
            "LLMNR Not Disabled",
            "=" * 50,
            "",
            "No GPO found disabling LLMNR (Link-Local Multicast Name Resolution).",
            "",
            "RISK: LLMNR is commonly exploited for:",
            "  - Credential capture using Responder",
            "  - NTLM relay attacks",
            "  - Man-in-the-middle attacks on name resolution",
            "",
            "GPO to disable LLMNR:",
            "  Computer Configuration > Administrative Templates > Network > DNS Client",
            "  > Turn off multicast name resolution = Enabled",
            "",
            "Registry: HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
            "  EnableMulticast = 0",
        ]
        write_file('\n'.join(output_lines), self.output_paths['findings'] / 'llmnr_enabled.txt', self.logger)
