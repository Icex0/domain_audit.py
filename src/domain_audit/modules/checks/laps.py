"""LAPS security checks."""

import io
import struct
from typing import Dict, List, Tuple, Optional
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv


class LAPSChecker:
    """Checks related to LAPS deployment and configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.domain = domain or ldap_conn.config.domain
    
    def check_laps(self):
        """Check LAPS deployment and configuration."""
        self.logger.info("---Checking if LAPS is deployed---")
        
        try:
            gpos = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter='(displayName=*LAPS*)',
                attributes=['displayName', 'gPCFileSysPath']
            )
            
            gpo_file = self.output_paths['data'] / 'laps_gpo.txt'
            
            if gpos:
                count = len(gpos)
                self.logger.success(f"[+] There are {count} GPOs with LAPS in their name")
                write_csv(gpos, gpo_file)
                
                for gpo in gpos:
                    gpo_dn = gpo.get('dn', '')
                    if 'CN={' in gpo_dn:
                        guid = gpo_dn.split('CN={')[1].split('}')[0]
                        
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
            laps_installed = False
            
            try:
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(&(objectClass=computer)(operatingSystem=*Windows*))',
                    attributes=['sAMAccountName', 'distinguishedName', 'ms-Mcs-AdmPwd', 'lastLogon', 'whenChanged', 'operatingSystem']
                )
                laps_installed = True
            except Exception:
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(&(objectClass=computer)(operatingSystem=*Windows*))',
                    attributes=['sAMAccountName', 'distinguishedName', 'lastLogon', 'whenChanged', 'operatingSystem']
                )
            
            if not laps_installed:
                self.logger.finding("LAPS schema not installed (ms-Mcs-AdmPwd attribute not found)")
                findings_file = self.output_paths['findings'] / 'laps_notenabled.txt'
                write_file("LAPS SCHEMA NOT INSTALLED", findings_file, self.logger)
            else:
                laps_computers = [c for c in all_computers if c.get('ms-Mcs-AdmPwd')]
                no_laps = [c for c in all_computers if not c.get('ms-Mcs-AdmPwd')]
                
                if laps_computers:
                    count = len(laps_computers)
                    self.logger.success(f"[+] There are {count} systems where LAPS is enabled")
                    write_lines([c.get('sAMAccountName', '') for c in laps_computers if c.get('sAMAccountName')], laps_file)
                    
                    readable_passwords = [c for c in laps_computers if c.get('ms-Mcs-AdmPwd')]
                    if readable_passwords:
                        self.logger.finding("The current user could read LAPS passwords")
                        pwd_file = self.output_paths['findings'] / 'laps_passwords_readable.txt'
                        pwd_data = [f"{c.get('sAMAccountName', 'unknown')}: {c.get('ms-Mcs-AdmPwd', '')}" for c in readable_passwords]
                        write_lines(pwd_data, pwd_file)
                    else:
                        self.logger.success("[+] The current user couldn't read any LAPS passwords")
                    
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
        """Check LAPS policy settings from GPO Registry.pol files."""
        self.logger.info("---Checking the LAPS policy for each GPO---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] LAPS policy check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            conn = SMBConnection(self.server, self.server)
            conn.login(self.username, self.password, self.domain)
            
            for gpo in gpos:
                gpo_name = gpo.get('displayName', 'Unknown')
                gpc_path = gpo.get('gPCFileSysPath', '')
                
                if not gpc_path:
                    self.logger.warning(f"[!] No gPCFileSysPath for GPO {gpo_name}")
                    continue
                
                # gPCFileSysPath format: \\domain.com\SysVol\domain.com\Policies\{GUID}
                # We need: domain.com/Policies/{GUID}/Machine/Registry.pol
                normalized = gpc_path.replace('\\', '/')
                # Remove leading slashes
                while normalized.startswith('/'):
                    normalized = normalized[1:]
                # Split: domain.com/SysVol/domain.com/Policies/{GUID}
                parts = normalized.split('/')
                # Find 'SysVol' or 'SYSVOL' index and take everything after it
                sysvol_idx = -1
                for i, part in enumerate(parts):
                    if part.lower() == 'sysvol':
                        sysvol_idx = i
                        break
                
                if sysvol_idx == -1 or sysvol_idx + 1 >= len(parts):
                    self.logger.warning(f"[!] Could not parse gPCFileSysPath for {gpo_name}: {gpc_path}")
                    continue
                
                # Join parts after SYSVOL: domain.com/Policies/{GUID}
                share_path = '/'.join(parts[sysvol_idx + 1:]) + '/Machine/Registry.pol'
                
                try:
                    content_buffer = io.BytesIO()
                    conn.getFile('SYSVOL', share_path, content_buffer.write)
                    content = content_buffer.getvalue()
                    
                    if content:
                        self._analyze_laps_policy(gpo_name, content)
                except Exception as e:
                    self.logger.warning(f"[!] Could not read Registry.pol for {gpo_name}: {e}")
            
            conn.logoff()
            
        except Exception as e:
            self.logger.error(f"[-] Error connecting to SYSVOL: {e}")
    
    def _parse_pol_file(self, content: bytes) -> List[Tuple[str, str, int, int, bytes]]:
        """
        Parse a Registry.pol file.
        
        Registry.pol format (all strings UTF-16LE):
        - Header: 4 bytes signature (PReg) + 4 bytes version
        - Entries: [key;value;type;size;data]
        
        Returns list of tuples: (key, value_name, type, size, data)
        """
        entries = []
        
        if len(content) < 8:
            return entries
        
        signature = content[:4]
        if signature != b'PReg':
            return entries
        
        # UTF-16LE markers
        OPEN_BRACKET = b'[\x00'
        CLOSE_BRACKET = b']\x00'
        SEMICOLON = b';\x00'
        NULL_TERM = b'\x00\x00'
        
        offset = 8
        while offset < len(content) - 2:
            # Find opening bracket
            if content[offset:offset+2] != OPEN_BRACKET:
                offset += 1
                continue
            
            offset += 2  # Skip [
            
            try:
                # Find key (null-terminated UTF-16LE string)
                key_end = content.find(NULL_TERM, offset)
                if key_end == -1:
                    break
                # Ensure we're on an even boundary for UTF-16
                if (key_end - offset) % 2 == 1:
                    key_end += 1
                key = content[offset:key_end].decode('utf-16-le', errors='ignore')
                offset = key_end + 2  # Skip null terminator
                
                # Skip semicolon
                if content[offset:offset+2] != SEMICOLON:
                    continue
                offset += 2
                
                # Find value name
                value_end = content.find(NULL_TERM, offset)
                if value_end == -1:
                    break
                if (value_end - offset) % 2 == 1:
                    value_end += 1
                value_name = content[offset:value_end].decode('utf-16-le', errors='ignore')
                offset = value_end + 2
                
                # Skip semicolon
                if content[offset:offset+2] != SEMICOLON:
                    continue
                offset += 2
                
                # Read type (4 bytes DWORD)
                if offset + 4 > len(content):
                    break
                reg_type = struct.unpack('<I', content[offset:offset+4])[0]
                offset += 4
                
                # Skip semicolon
                if content[offset:offset+2] != SEMICOLON:
                    continue
                offset += 2
                
                # Read size (4 bytes DWORD)
                if offset + 4 > len(content):
                    break
                data_size = struct.unpack('<I', content[offset:offset+4])[0]
                offset += 4
                
                # Skip semicolon
                if content[offset:offset+2] != SEMICOLON:
                    continue
                offset += 2
                
                # Read data
                if offset + data_size > len(content):
                    break
                data = content[offset:offset+data_size]
                offset += data_size
                
                # Skip closing bracket
                if content[offset:offset+2] == CLOSE_BRACKET:
                    offset += 2
                
                entries.append((key, value_name, reg_type, data_size, data))
                
            except Exception:
                offset += 1
                continue
        
        return entries
    
    def _analyze_laps_policy(self, gpo_name: str, content: bytes):
        """Analyze LAPS policy settings from parsed Registry.pol content."""
        entries = self._parse_pol_file(content)
        
        if not entries:
            self.logger.warning(f"[!] Could not parse Registry.pol for {gpo_name}")
            return
        
        laps_settings = {}
        for key, value_name, reg_type, data_size, data in entries:
            if 'LAPS' in key or 'AdmPwd' in key:
                if reg_type == 4:  # REG_DWORD
                    laps_settings[value_name] = struct.unpack('<I', data)[0] if data_size >= 4 else 0
                elif reg_type == 1:  # REG_SZ
                    laps_settings[value_name] = data.decode('utf-16-le', errors='ignore').rstrip('\x00')
                else:
                    laps_settings[value_name] = data
        
        if not laps_settings:
            self.logger.info(f"[*] No LAPS-specific settings found in {gpo_name}")
            return
        
        self.logger.info(f"[+] Found LAPS policy settings for {gpo_name}")
        
        policy_lines = [f"LAPS Policy: {gpo_name}", ""]
        findings = []
        
        admin_account = laps_settings.get('AdminAccountName')
        if admin_account is None or admin_account == '':
            self.logger.warning("[!] The LAPS local admin user is the default administrator account")
            findings.append("AdminAccountName: Using default administrator account")
            policy_lines.append("AdminAccountName: <default administrator>")
        else:
            self.logger.success(f"[+] The LAPS local admin user is not the default: {admin_account}")
            policy_lines.append(f"AdminAccountName: {admin_account}")
        
        pwd_complexity = laps_settings.get('PasswordComplexity')
        if pwd_complexity is not None:
            policy_lines.append(f"PasswordComplexity: {pwd_complexity}")
            if pwd_complexity == 4:
                self.logger.success("[+] The password complexity is 4")
            else:
                self.logger.finding(f"The password complexity is {pwd_complexity} (should be 4)")
                findings.append(f"PasswordComplexity: {pwd_complexity} (recommended: 4)")
        
        pwd_length = laps_settings.get('PasswordLength')
        if pwd_length is not None:
            policy_lines.append(f"PasswordLength: {pwd_length}")
            if pwd_length == 14:
                self.logger.warning("[!] The password length is the default 14")
                findings.append("PasswordLength: 14 (default, consider increasing)")
            elif pwd_length < 14:
                self.logger.finding(f"The password length is {pwd_length} (less than 14)")
                findings.append(f"PasswordLength: {pwd_length} (should be at least 14)")
            else:
                self.logger.success(f"[+] The password length is {pwd_length} (longer than default)")
        
        pwd_age = laps_settings.get('PasswordAgeDays')
        if pwd_age is not None:
            policy_lines.append(f"PasswordAgeDays: {pwd_age}")
            if pwd_age == 30:
                self.logger.warning("[!] The password age days is the default 30")
            elif pwd_age < 30:
                self.logger.success(f"[+] The password age days is {pwd_age} (less than 30)")
            else:
                self.logger.finding(f"The password age days is {pwd_age} (more than 30)")
                findings.append(f"PasswordAgeDays: {pwd_age} (should be 30 or less)")
        
        pwd_expiration = laps_settings.get('PwdExpirationProtectionEnabled')
        if pwd_expiration is not None:
            policy_lines.append(f"PwdExpirationProtectionEnabled: {pwd_expiration}")
            if pwd_expiration == 1:
                self.logger.success("[+] PwdExpirationProtectionEnabled is enabled")
            else:
                self.logger.finding("PwdExpirationProtectionEnabled is disabled or not configured")
                findings.append("PwdExpirationProtectionEnabled: Disabled (should be enabled)")
        else:
            self.logger.finding("PwdExpirationProtectionEnabled is not configured (defaults to disabled)")
            findings.append("PwdExpirationProtectionEnabled: Not configured (defaults to disabled)")
        
        admpwd_enabled = laps_settings.get('AdmPwdEnabled')
        if admpwd_enabled is not None:
            policy_lines.append(f"AdmPwdEnabled: {admpwd_enabled}")
            if admpwd_enabled == 1:
                self.logger.success("[+] The LAPS policy is enabled")
            else:
                self.logger.finding("The LAPS policy is disabled")
                findings.append("AdmPwdEnabled: Disabled (LAPS policy not active)")
        
        policy_lines.append("")
        if findings:
            policy_lines.append("Findings:")
            policy_lines.extend([f"  - {f}" for f in findings])
        else:
            policy_lines.append("Findings: None - LAPS policy is secure")
        
        policy_lines.append("")
        policy_lines.append("All Settings:")
        for key, value in laps_settings.items():
            policy_lines.append(f"  {key}: {value}")
        
        filepath = self.output_paths['findings'] / 'laps_policy.txt'
        write_file('\n'.join(policy_lines), filepath, self.logger)
