"""LAPS security checks."""

import struct
from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv
from ...utils.registry_pol import parse_pol_file
from ...utils.sysvol import MACHINE_REGISTRY_POL, SysvolClient, has_credentials


class LAPSChecker:
    """Checks related to LAPS deployment and configuration."""
    
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
    
    def check_laps(self):
        """Check LAPS deployment and configuration."""
        self.logger.info("---Checking if LAPS is deployed---")
        
        try:
            gpos = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter='(displayName=*LAPS*)',
                attributes=['displayName', 'cn', 'gPCFileSysPath']
            )
            
            gpo_file = self.output_paths['data'] / 'laps_gpo.txt'
            
            if gpos:
                count = len(gpos)
                self.logger.success(f"[+] There are {count} GPOs with LAPS in their name")
                write_csv(gpos, gpo_file)
                
                for gpo in gpos:
                    # cn of a groupPolicyContainer is the GPO GUID, e.g. {31B2F340-...}
                    guid = str(gpo.get('cn') or '').strip('{}')
                    if guid:
                        
                        linked_ous = self.ldap.query(
                            search_base=self.base_dn,
                            search_filter=f'(gPLink=*{guid}*)',
                            attributes=['name', 'distinguishedName']
                        )
                        
                        if linked_ous:
                            self.logger.success(f"[+] GPO {gpo.get('displayName')} is linked to {len(linked_ous)} OU(s)")
                            ou_file = self.output_paths['checks'] / 'laps_gpo_ou.txt'
                            ou_data = [f"{gpo.get('displayName')}:"]
                            for ou in linked_ous:
                                ou_data.append(f"  - {ou.get('name', 'unknown')}: {ou.get('distinguishedName', '')}")
                            write_lines(ou_data, ou_file)
                        else:
                            self.logger.finding(f"GPO {gpo.get('displayName')} isn't linked to any OU")
                
                self._check_laps_policy(gpos)
            else:
                self.logger.finding("There is no GPO with LAPS in their name")
            
            laps_file = self.output_paths['data'] / 'laps_computers_enabled.txt'
            
            # Check if LAPS schema is installed by probing for the attribute
            # in the schema partition, avoiding a noisy LDAP error on the main query
            laps_types = self._check_laps_schema()
            
            if laps_types is None:
                self.logger.warning("[!] LAPS deployment could not be checked - verify manually")
            elif not laps_types['legacy'] and not laps_types['windows']:
                self.logger.finding("LAPS schema not installed (neither legacy nor Windows LAPS attributes found)")
                findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                write_file("LAPS SCHEMA NOT INSTALLED", findings_file, self.logger)
            else:
                # Build attribute list based on which LAPS schema is installed
                # Only request attributes that exist to avoid LDAP errors
                attrs = ['sAMAccountName', 'distinguishedName',
                         'lastLogon', 'whenChanged', 'operatingSystem']
                
                if laps_types['legacy']:
                    attrs.extend(['ms-Mcs-AdmPwd', 'ms-Mcs-AdmPwdExpirationTime'])
                if laps_types['windows']:
                    attrs.extend(['msLAPS-PasswordExpirationTime', 'msLAPS-Password', 'msLAPS-EncryptedPassword'])
                
                # Enabled Windows computers, excluding DCs (SERVER_TRUST_ACCOUNT 0x2000)
                # and RODCs (PARTIAL_SECRETS_ACCOUNT 0x4000000): they have no local
                # administrator account for LAPS to manage.
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter=(
                        '(&(objectClass=computer)(operatingSystem=*Windows*)'
                        '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                        '(!(userAccountControl:1.2.840.113556.1.4.803:=8192))'
                        '(!(userAccountControl:1.2.840.113556.1.4.803:=67108864)))'
                    ),
                    attributes=attrs
                )
                
                # Detect LAPS deployment via expiration time attributes (readable by any user)
                laps_computers = [
                    c for c in all_computers
                    if c.get('ms-Mcs-AdmPwdExpirationTime') or c.get('msLAPS-PasswordExpirationTime')
                ]
                no_laps = [
                    c for c in all_computers
                    if not c.get('ms-Mcs-AdmPwdExpirationTime') and not c.get('msLAPS-PasswordExpirationTime')
                ]
                
                if laps_computers:
                    count = len(laps_computers)
                    self.logger.success(f"[+] There are {count} systems where LAPS is enabled")
                    write_lines([c.get('sAMAccountName', '') for c in laps_computers if c.get('sAMAccountName')], laps_file)
                    
                    # Check if the current user can read LAPS passwords (DA/delegated only)
                    self.logger.info("---Checking if current user has permissions to read LAPS passwords---")
                    # Legacy LAPS: ms-Mcs-AdmPwd (cleartext). Windows LAPS: msLAPS-Password
                    # (cleartext JSON, when AD encryption is off) or msLAPS-EncryptedPassword
                    # (only decryptable by the configured decryptor principal).
                    pwd_data = []
                    encrypted_readable = []
                    for c in laps_computers:
                        name = c.get('sAMAccountName', 'unknown')
                        if c.get('ms-Mcs-AdmPwd'):
                            pwd_data.append(f"{name}: {c.get('ms-Mcs-AdmPwd')} (legacy LAPS)")
                        if c.get('msLAPS-Password'):
                            pwd_data.append(f"{name}: {c.get('msLAPS-Password')} (Windows LAPS, not encrypted)")
                        if c.get('msLAPS-EncryptedPassword'):
                            encrypted_readable.append(name)
                    
                    if pwd_data:
                        self.logger.finding(f"The current user could read {len(pwd_data)} LAPS passwords")
                        write_lines(pwd_data, self.output_paths['findings'] / 'laps_passwords_readable.txt')
                    else:
                        self.logger.success("[+] The current user couldn't read any cleartext LAPS passwords")
                    
                    if encrypted_readable:
                        self.logger.warning(
                            f"[!] The current user can read the encrypted Windows LAPS password of {len(encrypted_readable)} "
                            "systems - it can only be decrypted by the configured decryptor (verify with netexec --laps / LAPS tooling)"
                        )
                        write_lines(encrypted_readable, self.output_paths['checks'] / 'laps_encrypted_passwords_readable.txt')
                    
                    self.logger.info("---Checking for computers without LAPS---")
                    if no_laps:
                        no_laps_file = self.output_paths['findings'] / 'laps_computers_disabled.txt'
                        self.logger.finding(f"There are {len(no_laps)} Windows systems where LAPS isn't enabled")
                        write_lines([c.get('sAMAccountName', '') for c in no_laps if c.get('sAMAccountName')], no_laps_file)
                    else:
                        self.logger.success("[+] All Windows systems have LAPS enabled")
                else:
                    self.logger.finding("There are no systems where LAPS is enabled")
                    findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                    write_file("LAPS NOT ENABLED ON ANY COMPUTER", findings_file, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking LAPS: {e}")
    
    def _check_laps_policy(self, gpos: List[Dict]):
        """Check LAPS policy settings from the GPOs' Machine/Registry.pol."""
        self.logger.info("---Checking the LAPS policy for each GPO---")
        
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning("[!] LAPS policy check requires SMB credentials")
            return
        
        try:
            sysvol = SysvolClient.shared(self.ldap, self.domain, self.username, self.password, self.hashes, self.logger)
        except Exception as e:
            self.logger.error(f"[-] Error connecting to SYSVOL: {e}")
            return
        
        for gpo in gpos:
            gpo_name = gpo.get('displayName', 'Unknown')
            # cn of a groupPolicyContainer is the GPO GUID; the SYSVOL folder has the same name
            guid = str(gpo.get('cn') or '')
            if not guid.startswith('{'):
                self.logger.warning(f"[!] Could not determine the GUID of GPO {gpo_name}")
                continue
            content = sysvol.gpo_file(guid, MACHINE_REGISTRY_POL)
            if content:
                self._analyze_laps_policy(gpo_name, content)
            else:
                self.logger.info(f"[*] No Machine/Registry.pol for {gpo_name}")

    # Registry.pol keys. Windows LAPS GPO settings live under
    # Software\Microsoft\Windows\CurrentVersion\Policies\LAPS; legacy Microsoft
    # LAPS under Software\Policies\Microsoft Services\AdmPwd.
    WINDOWS_LAPS_KEY = 'software\\microsoft\\windows\\currentversion\\policies\\laps'
    LEGACY_LAPS_KEY = 'software\\policies\\microsoft services\\admpwd'

    def _analyze_laps_policy(self, gpo_name: str, content: bytes):
        """Analyze LAPS policy settings from parsed Registry.pol content."""
        entries = parse_pol_file(content)
        
        if not entries:
            self.logger.warning(f"[!] Could not parse Registry.pol for {gpo_name}")
            return
        
        settings = {'windows': {}, 'legacy': {}}
        for key, value_name, reg_type, data_size, data in entries:
            key_lower = key.lower().rstrip('\\')
            if key_lower == self.WINDOWS_LAPS_KEY:
                kind = 'windows'
            elif key_lower == self.LEGACY_LAPS_KEY:
                kind = 'legacy'
            else:
                continue
            if reg_type == 4:  # REG_DWORD
                settings[kind][value_name] = struct.unpack('<I', data[:4])[0] if data_size >= 4 else 0
            elif reg_type in (1, 2):  # REG_SZ / REG_EXPAND_SZ
                settings[kind][value_name] = data.decode('utf-16-le', errors='ignore').rstrip('\x00')
            else:
                settings[kind][value_name] = data
        
        if not settings['windows'] and not settings['legacy']:
            self.logger.info(f"[*] No LAPS-specific settings found in {gpo_name}")
            return
        
        self.logger.info(f"[+] Found LAPS policy settings for {gpo_name}")
        policy_lines = [f"LAPS Policy: {gpo_name}", ""]
        findings = []
        
        for kind in ('windows', 'legacy'):
            if settings[kind]:
                label = 'Windows LAPS' if kind == 'windows' else 'Legacy Microsoft LAPS'
                policy_lines.append(f"[{label}]")
                findings.extend(self._evaluate_laps_settings(kind, settings[kind], policy_lines))
                policy_lines.append("")
        
        if findings:
            policy_lines.append("Findings:")
            policy_lines.extend([f"  - {f}" for f in findings])
        else:
            policy_lines.append("Findings: None - LAPS policy is secure")
        
        policy_lines.append("")
        policy_lines.append("All Settings:")
        for kind in ('windows', 'legacy'):
            for key, value in settings[kind].items():
                policy_lines.append(f"  {key}: {value}")
        
        # Only report as a finding if the policy is actually weak
        if findings:
            filepath = self.output_paths['findings'] / 'laps_policy.txt'
        else:
            filepath = self.output_paths['checks'] / 'laps_policy.txt'
        write_file('\n'.join(policy_lines), filepath, self.logger)
    
    def _evaluate_laps_settings(self, kind: str, laps_settings: Dict, policy_lines: List[str]) -> List[str]:
        """Evaluate one set of LAPS settings. Missing values use the documented defaults
        (Windows LAPS: https://learn.microsoft.com/windows-server/identity/laps/laps-management-policy-settings).
        """
        findings = []
        prefix = 'Windows LAPS' if kind == 'windows' else 'Legacy LAPS'
        
        if kind == 'windows':
            # BackupDirectory: 0 = disabled (default), 1 = Microsoft Entra ID, 2 = Active Directory
            backup = laps_settings.get('BackupDirectory', 0)
            backup_desc = {0: 'Disabled', 1: 'Microsoft Entra ID', 2: 'Active Directory'}.get(backup, f'Unknown ({backup})')
            policy_lines.append(f"BackupDirectory: {backup} ({backup_desc})")
            if backup == 0:
                self.logger.finding(f"{prefix}: BackupDirectory is disabled - passwords aren't backed up, LAPS isn't active")
                findings.append(f"{prefix}: BackupDirectory disabled (LAPS not active)")
            else:
                self.logger.success(f"[+] {prefix}: passwords are backed up to {backup_desc}")
            admin_name_key, expiration_key, expiration_default = 'AdministratorAccountName', 'PasswordExpirationProtectionEnabled', 1
        else:
            enabled = laps_settings.get('AdmPwdEnabled')
            if enabled is not None:
                policy_lines.append(f"AdmPwdEnabled: {enabled}")
                if enabled == 1:
                    self.logger.success(f"[+] {prefix}: the LAPS policy is enabled")
                else:
                    self.logger.finding(f"{prefix}: the LAPS policy is disabled")
                    findings.append("AdmPwdEnabled: Disabled (LAPS policy not active)")
            admin_name_key, expiration_key, expiration_default = 'AdminAccountName', 'PwdExpirationProtectionEnabled', 0
        
        admin_account = laps_settings.get(admin_name_key)
        if not admin_account:
            self.logger.warning(f"[!] {prefix}: the LAPS local admin user is the default administrator account")
            findings.append(f"{admin_name_key}: Using default administrator account")
            policy_lines.append(f"{admin_name_key}: <default administrator>")
        else:
            self.logger.success(f"[+] {prefix}: the LAPS local admin user is not the default: {admin_account}")
            policy_lines.append(f"{admin_name_key}: {admin_account}")
        
        # PasswordComplexity: 4 = all character sets (default). Windows LAPS also has
        # 5 (improved readability) and 6-8 (passphrases).
        pwd_complexity = laps_settings.get('PasswordComplexity')
        if pwd_complexity is not None:
            policy_lines.append(f"PasswordComplexity: {pwd_complexity}")
            if pwd_complexity >= 4:
                self.logger.success(f"[+] {prefix}: the password complexity is {pwd_complexity}")
            else:
                self.logger.finding(f"{prefix}: the password complexity is {pwd_complexity} (should be 4 or higher)")
                findings.append(f"PasswordComplexity: {pwd_complexity} (recommended: 4 or higher)")
        
        pwd_length = laps_settings.get('PasswordLength')
        if pwd_length is not None:
            policy_lines.append(f"PasswordLength: {pwd_length}")
            if pwd_length == 14:
                self.logger.warning(f"[!] {prefix}: the password length is the default 14")
                findings.append("PasswordLength: 14 (default, consider increasing)")
            elif pwd_length < 14:
                self.logger.finding(f"{prefix}: the password length is {pwd_length} (less than 14)")
                findings.append(f"PasswordLength: {pwd_length} (should be at least 14)")
            else:
                self.logger.success(f"[+] {prefix}: the password length is {pwd_length} (longer than default)")
        
        pwd_age = laps_settings.get('PasswordAgeDays')
        if pwd_age is not None:
            policy_lines.append(f"PasswordAgeDays: {pwd_age}")
            if pwd_age == 30:
                self.logger.warning(f"[!] {prefix}: the password age days is the default 30")
            elif pwd_age < 30:
                self.logger.success(f"[+] {prefix}: the password age days is {pwd_age} (less than 30)")
            else:
                self.logger.finding(f"{prefix}: the password age days is {pwd_age} (more than 30)")
                findings.append(f"PasswordAgeDays: {pwd_age} (should be 30 or less)")
        
        # Windows LAPS enables expiration protection by default; legacy LAPS doesn't
        pwd_expiration = laps_settings.get(expiration_key, expiration_default)
        configured = 'configured' if expiration_key in laps_settings else 'default'
        policy_lines.append(f"{expiration_key}: {pwd_expiration} ({configured})")
        if pwd_expiration == 1:
            self.logger.success(f"[+] {prefix}: {expiration_key} is enabled ({configured})")
        else:
            self.logger.finding(f"{prefix}: {expiration_key} is disabled ({configured})")
            findings.append(f"{expiration_key}: Disabled ({configured}, should be enabled)")
        
        if kind == 'windows':
            # ADPasswordEncryptionEnabled defaults to 1; 0 stores the password in
            # cleartext in msLAPS-Password
            encryption = laps_settings.get('ADPasswordEncryptionEnabled', 1)
            policy_lines.append(f"ADPasswordEncryptionEnabled: {encryption}")
            if encryption == 0 and laps_settings.get('BackupDirectory', 0) == 2:
                self.logger.finding(f"{prefix}: password encryption in AD is disabled (stored in cleartext in msLAPS-Password)")
                findings.append("ADPasswordEncryptionEnabled: Disabled (password stored unencrypted in AD)")
        
        return findings
    
    def _check_laps_schema(self) -> dict:
        """Check which LAPS schema extensions are installed.
        
        Probes the AD schema for ms-Mcs-AdmPwd (legacy LAPS) and
        msLAPS-Password (Windows LAPS) attribute definitions.
        
        Returns:
            Dict with 'legacy' and 'windows' booleans.
        """
        result = {'legacy': False, 'windows': False}
        try:
            config_dn = f"CN=Schema,CN=Configuration,{self.base_dn}"
            try:
                config_dn = f"CN=Schema,{self.ldap.get_config_dn()}"
            except Exception as e:
                self.logger.debug(f"Could not read the configuration NC, using {config_dn}: {e}")
            
            results = self.ldap.query(
                search_base=config_dn,
                search_filter='(|(lDAPDisplayName=ms-Mcs-AdmPwd)(lDAPDisplayName=msLAPS-Password))',
                attributes=['lDAPDisplayName']
            )
            for r in results:
                attr_name = r.get('lDAPDisplayName', '')
                if attr_name == 'ms-Mcs-AdmPwd':
                    result['legacy'] = True
                elif attr_name == 'msLAPS-Password':
                    result['windows'] = True
        except Exception as e:
            self.logger.warning(f"[!] Could not read the schema to detect LAPS: {e}")
            return None
        return result
