"""NTLM security checks: NTLMv1 support, NTLM restrictions and LM hash storage.

All settings are read from the GPOs in SYSVOL (Registry.pol and the Security
Options in GptTmpl.inf [Registry Values]) via the shared utils.sysvol client.
"""

from pathlib import Path
from typing import Dict, List, Optional

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file
from ...utils.dc import get_domain_controllers
from ...utils.sysvol import SysvolClient, has_credentials
from ...utils.gpo_scope import GPOScope


# LmCompatibilityLevel values and their meanings
LM_COMPATIBILITY_LEVELS = {
    0: "Send LM & NTLM responses",
    1: "Send LM & NTLM - use NTLMv2 session security if negotiated",
    2: "Send NTLM response only",
    3: "Send NTLMv2 response only",
    4: "Send NTLMv2 response only, refuse LM",
    5: "Send NTLMv2 response only, refuse LM & NTLM",
}

# Registry value name (lowercase) -> setting key. Value names are unique, so the
# same mapping serves Registry.pol entries and GptTmpl.inf [Registry Values].
NTLM_VALUES = {
    'lmcompatibilitylevel': 'lm_compatibility_level',   # Lsa
    'nolmhash': 'no_lm_hash',                           # Lsa
    'restrictntlmindomain': 'restrict_ntlm_domain',     # Netlogon\Parameters (0/1/3/5/7)
    'auditntlmindomain': 'audit_ntlm_domain',           # Netlogon\Parameters (0/1/3/5/7)
    'restrictsendingntlmtraffic': 'restrict_sending',   # Lsa\MSV1_0 (0/1/2)
    'restrictreceivingntlmtraffic': 'restrict_receiving',  # Lsa\MSV1_0 (0/1/2)
    'auditreceivingntlmtraffic': 'audit_receiving',     # Lsa\MSV1_0 (0/1/2)
}

RESTRICT_NTLM_DOMAIN = {0: "Disabled (allow all)", 1: "Deny for domain accounts to domain servers",
                        3: "Deny for domain accounts", 5: "Deny for domain servers", 7: "Deny all"}
AUDIT_NTLM_DOMAIN = {0: "Disabled", 1: "Enable for domain accounts to domain servers",
                     3: "Enable for domain accounts", 5: "Enable for domain servers", 7: "Enable all"}
RESTRICT_SENDING = {0: "Allow all", 1: "Audit all (no blocking)", 2: "Deny all"}
RESTRICT_RECEIVING = {0: "Allow all", 1: "Deny domain accounts", 2: "Deny all"}
AUDIT_RECEIVING = {0: "Disabled", 1: "Enable auditing for domain accounts", 2: "Enable auditing for all accounts"}


def gpo_dword_settings(sysvol: SysvolClient, guids: List[str], value_names: Dict[str, str],
                       key_contains: Optional[str] = None) -> Dict[str, Dict[str, int]]:
    """{GPO GUID upper: {setting: DWORD value}} from Registry.pol and GptTmpl.inf.

    value_names maps lowercase registry value names to setting keys. Registry.pol
    values override GptTmpl.inf values of the same GPO. key_contains optionally
    restricts Registry.pol entries to keys containing this (lowercase) text.
    """
    import struct
    result: Dict[str, Dict[str, int]] = {}
    for guid in guids:
        settings: Dict[str, int] = {}
        registry_values = sysvol.gpttmpl(guid).get('Registry Values', {})
        for reg_path, raw in registry_values.items():
            name = reg_path.rsplit('\\', 1)[-1].lower()
            if name not in value_names or (key_contains and key_contains not in reg_path.lower()):
                continue
            parts = (raw or '').split(',')
            if len(parts) >= 2 and parts[0].strip() == '4':   # REG_DWORD
                try:
                    settings[value_names[name]] = int(parts[1].strip())
                except ValueError:
                    pass  # malformed value - ignore this setting
        for key, value_name, reg_type, _size, data in sysvol.registry_pol(guid):
            name = value_name.lower()
            if name not in value_names or (key_contains and key_contains not in key.lower()):
                continue
            if reg_type == 4 and len(data) >= 4:  # REG_DWORD
                settings[value_names[name]] = struct.unpack('<I', data[:4])[0]
        if settings:
            result[guid.upper()] = settings
    return result


class NTLMChecker:
    """Check NTLM security settings including NTLMv1 support and NTLM restrictions."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain or ldap_conn.config.domain
        self._settings = None
        self._scope = None

    def check_ntlm(self):
        """Run all NTLM-related security checks."""
        self._check_ntlmv1_support()
        self._check_ntlm_restrictions()
        self._check_lm_hash_storage()

    # ---------- data ----------

    @property
    def scope(self) -> GPOScope:
        if self._scope is None:
            self._scope = GPOScope(self.ldap, self.logger)
        return self._scope

    def _gpo_settings(self) -> Dict[str, Dict[str, int]]:
        """NTLM settings per linked GPO (cached for the three checks)."""
        if self._settings is None:
            sysvol = SysvolClient.shared(self.ldap, self.domain, self.username, self.password, self.hashes, self.logger)
            linked = self.scope.linked_gpo_guids()
            guids = [g for g in sysvol.gpo_folders() if not linked or g.upper() in linked]
            self._settings = gpo_dword_settings(sysvol, guids, NTLM_VALUES)
        return self._settings

    def _gpo_name(self, guid: str) -> str:
        self.scope.load()
        info = self.scope.gpos.get(guid.upper())
        return info.name if info else guid

    def _requirements_met(self, label: str) -> bool:
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning(f"[!] {label} requires SMB credentials")
            return False
        return True

    # ---------- NTLMv1 ----------

    def _check_ntlmv1_support(self):
        """Check LmCompatibilityLevel set via GPO.

        Levels 0-2 make machines send NTLMv1; DCs only refuse NTLMv1 at level 5
        (levels 3 and 4 still accept it).
        """
        self.logger.info("---Checking for NTLMv1 support on Domain Controllers---")
        if not self._requirements_met("NTLMv1 check"):
            return

        try:
            dcs = get_domain_controllers(self.ldap, ['dNSHostName', 'name', 'operatingSystem'])
            if not dcs:
                self.logger.warning("[!] No domain controllers found")
                return

            gpo_settings = [
                {'gpo_name': self._gpo_name(guid), 'lm_level': cfg['lm_compatibility_level'],
                 'description': LM_COMPATIBILITY_LEVELS.get(cfg['lm_compatibility_level'],
                                                            f"Unknown ({cfg['lm_compatibility_level']})")}
                for guid, cfg in self._gpo_settings().items() if 'lm_compatibility_level' in cfg
            ]
            ntlmv1_findings = [f"{s['gpo_name']}: LmCompatibilityLevel={s['lm_level']} ({s['description']})"
                               for s in gpo_settings if s['lm_level'] <= 2]

            if ntlmv1_findings:
                self.logger.finding(f"NTLMv1 supported in {len(ntlmv1_findings)} GPO(s) - vulnerable to downgrade/relay attacks")
                output_lines = [
                    "NTLMv1 Support Detected",
                    "=" * 50,
                    "",
                    "RISK: NTLMv1 is vulnerable to:",
                    "  - Downgrade attacks (forcing NTLMv1 instead of NTLMv2)",
                    "  - Relay attacks with easier hash cracking",
                    "  - Rainbow table attacks on captured hashes",
                    "",
                    "RECOMMENDATION: Set LmCompatibilityLevel to 3 or higher",
                    "  3 = Send NTLMv2 response only",
                    "  4 = Send NTLMv2 response only, refuse LM",
                    "  5 = Send NTLMv2 response only, refuse LM & NTLM (most secure)",
                    "",
                    "Affected GPOs:",
                ] + [f"  - {f}" for f in ntlmv1_findings]
                write_file('\n'.join(output_lines), self.output_paths['findings'] / 'ntlmv1_supported.txt', self.logger)
            elif gpo_settings:
                # All settings are >= 3, so no machine *sends* NTLMv1. Only level 5
                # makes a DC *refuse* NTLMv1 (levels 3 and 4 still accept it).
                accepting = [s for s in gpo_settings if s['lm_level'] < 5]
                if accepting:
                    levels = ', '.join(sorted({str(s['lm_level']) for s in accepting}))
                    self.logger.warning(
                        f"[!] LmCompatibilityLevel {levels} found: clients only send NTLMv2, but DCs at level < 5 "
                        "still accept NTLMv1 authentication (verify which GPO applies to the DCs)"
                    )
                else:
                    self.logger.success("[+] NTLMv1 is refused (LmCompatibilityLevel 5 in all GPOs)")
                output_lines = ["LmCompatibilityLevel Settings", "",
                                "Levels 3-5 only send NTLMv2; only level 5 makes a DC refuse NTLMv1.", ""]
                output_lines += [f"{s['gpo_name']}: Level {s['lm_level']} - {s['description']}" for s in gpo_settings]
                write_file('\n'.join(output_lines), self.output_paths['checks'] / 'ntlmv1_settings.txt', self.logger)
            else:
                self._report_os_defaults(dcs)
        except Exception as e:
            self.logger.error(f"[-] Error checking NTLMv1 support: {e}")

    def _report_os_defaults(self, dcs: List[Dict]):
        """No GPO sets LmCompatibilityLevel: report the DCs' OS defaults."""
        default_vulnerable = self._check_dc_os_defaults(dcs)
        if default_vulnerable:
            self.logger.warning("[!] No LmCompatibilityLevel GPO found - DCs on legacy OS may use vulnerable defaults unless set via local GPO/registry/MDM (verify on host)")
            output_lines = [
                "NTLMv1 Support (OS Default)",
                "=" * 50,
                "",
                "No LmCompatibilityLevel GPO setting found.",
                "",
                "RISK: Domain Controllers are running legacy operating systems with vulnerable defaults:",
            ] + [f"  - {dc_name}: {os_name} (default level {level})" for dc_name, os_name, level in default_vulnerable] + [
                "",
                "These OS defaults allow NTLMv1:",
                "  - Server 2000/XP: Level 1 (NTLMv1)",
                "  - Server 2003: Level 2 (NTLMv1 with v2 session security)",
                "",
                "RECOMMENDATION: Set LmCompatibilityLevel to 3+ via GPO",
                "Verify by running Responder and coerce the DC to check actual behavior"
            ]
            write_file('\n'.join(output_lines), self.output_paths['findings'] / 'ntlmv1_supported.txt', self.logger)
            return

        self.logger.warning("[!] No LmCompatibilityLevel GPO found - OS defaults apply")
        self.logger.info("[*] DCs use the OS default level 3: they only send NTLMv2, but still accept NTLMv1 (level 5 refuses it)")
        output_lines = ["No LmCompatibilityLevel GPO setting found.", "", "Domain Controllers (OS default level 3):"]
        output_lines += [f"  - {dc.get('name', dc.get('dNSHostName', 'Unknown'))}: {dc.get('operatingSystem', 'Unknown')}"
                         for dc in dcs]
        output_lines += [
            "",
            "OS defaults:",
            "  - Server 2008 and newer: Level 3 (sends NTLMv2 only, still accepts NTLMv1 - set 5 to refuse it)",
            "  - Server 2003: Level 2 (NTLMv1 with v2 session) - Vulnerable",
            "  - Server 2000/XP: Level 1 (NTLMv1) - Vulnerable",
            "",
            "Verify by running Responder and coerce the DC to check if LmCompatibilityLevel",
            "is set at the local registry level only instead of GPO"
        ]
        write_file('\n'.join(output_lines), self.output_paths['checks'] / 'ntlmv1_settings.txt', self.logger)

    @staticmethod
    def _check_dc_os_defaults(dcs: List[Dict]) -> List[tuple]:
        """DCs on legacy OS with vulnerable LmCompatibilityLevel defaults: (name, os, level)."""
        vulnerable = []
        for dc in dcs:
            os_name = dc.get('operatingSystem') or ''
            os_lower = os_name.lower()
            if '2000' in os_lower or 'windows xp' in os_lower:
                level = 1
            elif '2003' in os_lower:
                level = 2
            else:
                continue  # Vista / 2008 and newer default to level 3
            vulnerable.append((dc.get('name', dc.get('dNSHostName', 'Unknown')), os_name, level))
        return vulnerable

    # ---------- NTLM restrictions ----------

    def _check_ntlm_restrictions(self):
        """Check whether NTLM authentication is restricted in the domain.

        - RestrictNTLMInDomain (DC): any non-zero value restricts
        - RestrictSendingNTLMTraffic (clients): 2 = deny (1 is audit only)
        - RestrictReceivingNTLMTraffic (servers): 1 or 2 deny
        """
        self.logger.info("---Checking NTLM restriction policies---")
        if not self._requirements_met("NTLM restriction check"):
            return

        try:
            keys = ('restrict_ntlm_domain', 'audit_ntlm_domain', 'restrict_sending', 'restrict_receiving', 'audit_receiving')
            policies = [(guid, {k: v for k, v in cfg.items() if k in keys})
                        for guid, cfg in self._gpo_settings().items()]
            policies = [(guid, cfg) for guid, cfg in policies if cfg]

            def restricted(cfg):
                return (cfg.get('restrict_ntlm_domain', 0) > 0 or cfg.get('restrict_sending', 0) >= 2
                        or cfg.get('restrict_receiving', 0) >= 1)

            if any(restricted(cfg) for _, cfg in policies):
                self.logger.success("[+] NTLM restrictions are configured")
                output_lines = ["NTLM Restriction Policies", "=" * 50, ""]
                for guid, cfg in policies:
                    output_lines.append(f"GPO: {self._gpo_name(guid)}")
                    for key, label, names in (
                        ('restrict_ntlm_domain', 'RestrictNTLMInDomain (DC)', RESTRICT_NTLM_DOMAIN),
                        ('restrict_sending', 'RestrictSendingNTLMTraffic (Clients)', RESTRICT_SENDING),
                        ('restrict_receiving', 'RestrictReceivingNTLMTraffic (Servers)', RESTRICT_RECEIVING),
                        ('audit_ntlm_domain', 'AuditNTLMInDomain (DC)', AUDIT_NTLM_DOMAIN),
                        ('audit_receiving', 'AuditReceivingNTLMTraffic (Servers)', AUDIT_RECEIVING),
                    ):
                        if key in cfg:
                            output_lines.append(f"  {label}: {cfg[key]} - {names.get(cfg[key], f'Unknown ({cfg[key]})')}")
                    output_lines.append("")
                write_file('\n'.join(output_lines), self.output_paths['checks'] / 'ntlm_restrictions.txt', self.logger)
                return

            if policies:
                self.logger.info("[*] NTLM audit settings found but no restrictions enforced")
            self.logger.warning("[!] No domain GPO restricts NTLM - may be unrestricted unless set via local GPO/registry/MDM (verify on host)")
            output_lines = [
                "NTLM Not Restricted",
                "=" * 50,
                "",
                "No NTLM restriction policies were found in GPOs.",
                "",
                "RISK: NTLM authentication is enabled domain-wide, which allows:",
                "  - NTLM relay attacks",
                "  - Pass-the-hash attacks",
                "  - Credential capture and offline cracking",
                "",
                "RECOMMENDATION: Consider implementing NTLM restrictions:",
                "  1. Enable NTLM auditing first to identify dependencies",
                "  2. Add exceptions for required services",
                "  3. Gradually restrict NTLM traffic",
                "",
                "Relevant GPO settings:",
                "  - Network security: Restrict NTLM: NTLM authentication in this domain",
                "  - Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers",
                "  - Network security: Restrict NTLM: Audit NTLM authentication in this domain",
            ]
            write_file('\n'.join(output_lines), self.output_paths['findings'] / 'ntlm_not_restricted.txt', self.logger)
        except Exception as e:
            self.logger.error(f"[-] Error checking NTLM restrictions: {e}")

    # ---------- LM hashes ----------

    def _check_lm_hash_storage(self):
        """Check whether a GPO re-enables storing LM hashes (NoLMHash = 0).

        "Network security: Do not store LAN Manager hash value on next password
        change" (Lsa\\NoLMHash) is enabled by default since Vista / Server 2008.
        A GPO setting it to 0 makes Windows store the LM hash (crackable in
        seconds) for passwords up to 14 characters - in AD when it applies to DCs,
        in the local SAM on other computers. Evaluated per computer with GPO scope.
        """
        self.logger.info("---Checking LM hash storage (NoLMHash)---")
        if not self._requirements_met("LM hash check"):
            return

        try:
            values = {guid: cfg['no_lm_hash'] for guid, cfg in self._gpo_settings().items() if 'no_lm_hash' in cfg}
            enabling = [self._gpo_name(g) for g, v in values.items() if v == 0]
            if not enabling:
                self.logger.success("[+] No GPO enables LM hash storage (NoLMHash is not set to 0)")
                return

            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'distinguishedName', 'objectSid', 'primaryGroupID', 'userAccountControl']
            )
            affected, unclear = [], []
            for computer in computers:
                result = self.scope.effective_value(computer, values)
                name = computer.get('sAMAccountName', computer['distinguishedName'])
                if result.status == 'configured' and result.value == 0:
                    dc_note = ' (DC - LM hashes stored in Active Directory)' if int(computer.get('userAccountControl') or 0) & 0x2000 else ''
                    affected.append(f"{name}{dc_note}")
                elif result.status in ('conflict', 'uncertain'):
                    unclear.append(f"{name}: {result.status} - {result.reason}")

            if affected:
                self.logger.finding(f"LM hashes are stored on {len(affected)} computers (NoLMHash=0 via GPO: {', '.join(enabling)})")
                write_file('\n'.join([f"GPOs setting NoLMHash=0: {', '.join(enabling)}", "",
                                      "Computers where it applies:"] + [f"  {a}" for a in sorted(affected)]),
                           self.output_paths['findings'] / 'lm_hash_storage.txt', self.logger)
            else:
                self.logger.success(f"[+] GPO(s) setting NoLMHash=0 ({', '.join(enabling)}) don't apply to any computer")
            if unclear:
                self.logger.warning(f"[!] NoLMHash scope couldn't be determined for {len(unclear)} computers - verify manually")
                write_file('\n'.join(unclear), self.output_paths['checks'] / 'lm_hash_storage_verify.txt', self.logger)
        except Exception as e:
            self.logger.error(f"[-] Error checking LM hash storage: {e}")
