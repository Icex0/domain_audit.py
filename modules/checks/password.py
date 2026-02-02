"""Password policy security checks."""

import configparser
import io
from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv

# Default Domain Policy GUID
DEFAULT_DOMAIN_POLICY_GUID = "{31B2F340-016D-11D2-945F-00C04FB984F9}"

# Default Kerberos policy values (Windows defaults)
DEFAULT_KERBEROS_POLICY = {
    'MaxTicketAge': 10,       # hours - TGT lifetime
    'MaxRenewAge': 7,         # days - TGT renewal lifetime
    'MaxServiceAge': 600,     # minutes - Service ticket lifetime
    'MaxClockSkew': 5,        # minutes - Clock skew tolerance
    'TicketValidateClient': 1 # Validate client
}


class PasswordChecker:
    """Checks related to password policies and Kerberos settings."""
    
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
    
    def check_password_policy(self):
        """Check domain password and lockout policy."""
        self.logger.info("---Checking password policy---")
        
        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=domain)',
                attributes=[
                    'minPwdLength', 'pwdHistoryLength', 'pwdProperties',
                    'lockoutThreshold', 'lockoutDuration', 'lockOutObservationWindow',
                    'maxPwdAge', 'minPwdAge'
                ]
            )
            
            if not results:
                self.logger.error("[-] Could not retrieve password policy")
                return
            
            policy = results[0]
            findings = []
            
            min_length = policy.get('minPwdLength', 0)
            if min_length >= 12:
                self.logger.success(f"[+] Password length requirement is {min_length} (>= 12)")
            else:
                self.logger.finding(f"Password length requirement is {min_length} characters")
                findings.append(f"Minimum password length is only {min_length}")
            
            pwd_properties = policy.get('pwdProperties', 0)
            if pwd_properties & 1:
                self.logger.success("[+] PasswordComplexity is enabled")
            else:
                self.logger.finding("PasswordComplexity is disabled!")
                findings.append("Password complexity is disabled")
            
            lockout_threshold = policy.get('lockoutThreshold', 0)
            if lockout_threshold == 0:
                self.logger.finding("LockOutBadCount is 0, accounts won't be locked!")
                findings.append("Account lockout is disabled")
            elif lockout_threshold > 6:
                self.logger.finding(f"LockOutBadCount is {lockout_threshold} (> 6)")
                findings.append(f"Lockout threshold is too high ({lockout_threshold})")
            else:
                self.logger.success(f"[+] LockOutBadCount is {lockout_threshold}")
            
            filepath = self.output_paths['findings'] / 'passwordpolicy.txt'
            policy_lines = [
                "Password Policy:",
                f"  Minimum Password Length: {policy.get('minPwdLength', 'N/A')}",
                f"  Password History Length: {policy.get('pwdHistoryLength', 'N/A')}",
                f"  Password Properties: {policy.get('pwdProperties', 'N/A')}",
                f"  Lockout Threshold: {policy.get('lockoutThreshold', 'N/A')}",
                f"  Lockout Duration: {policy.get('lockoutDuration', 'N/A')}",
                f"  Lockout Observation Window: {policy.get('lockOutObservationWindow', 'N/A')}",
                f"  Maximum Password Age: {policy.get('maxPwdAge', 'N/A')}",
                f"  Minimum Password Age: {policy.get('minPwdAge', 'N/A')}",
                "",
                "Issues:",
            ]
            if findings:
                policy_lines.extend(findings)
            else:
                policy_lines.append("  None - password policy is secure")
            policy_lines.extend([
                "",
                "Raw Data:",
            ])
            for key, value in policy.items():
                if key != 'dn':
                    policy_lines.append(f"  {key}: {value}")
            write_file('\n'.join(policy_lines), filepath, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking password policy: {e}")
    
    def check_kerberos_policy(self):
        """Check Kerberos policy settings from Default Domain Policy in SYSVOL."""
        self.logger.info("---Checking password policy Kerberos---")
        
        if not self.username or not self.password:
            self.logger.warning("[!] Kerberos policy check requires SMB credentials")
            return
        
        try:
            from impacket.smbconnection import SMBConnection
        except ImportError:
            self.logger.error("[-] impacket not available for SYSVOL access")
            return
        
        try:
            # Get a domain controller
            dcs = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                attributes=['dNSHostName', 'name']
            )
            
            if not dcs:
                self.logger.warning("[!] No domain controllers found, using configured server")
                dc_hostname = self.server
            else:
                dc_hostname = dcs[0].get('dNSHostName', self.server)
            
            # Connect to SYSVOL
            conn = SMBConnection(dc_hostname, dc_hostname)
            conn.login(self.username, self.password, self.domain)
            
            # Path to GptTmpl.inf in Default Domain Policy
            gpt_path = f"{self.domain}/Policies/{DEFAULT_DOMAIN_POLICY_GUID}/MACHINE/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
            
            try:
                # Use getFile which handles read-only access properly
                content_buffer = io.BytesIO()
                conn.getFile('SYSVOL', gpt_path, content_buffer.write)
                content = content_buffer.getvalue()
                conn.logoff()
            except Exception as e:
                self.logger.error(f"[-] Could not read GptTmpl.inf from SYSVOL: {e}")
                conn.logoff()
                return
            
            if not content:
                self.logger.warning("[!] GptTmpl.inf is empty or not readable")
                return
            
            # Parse the INI-style file
            kerberos_policy = self._parse_kerberos_policy(content)
            
            if not kerberos_policy:
                self.logger.info("[*] No Kerberos policy section found (using Windows defaults)")
                kerberos_policy = DEFAULT_KERBEROS_POLICY.copy()
            
            # Analyze and report findings - using Microsoft recommended defaults
            findings = []
            policy_lines = ["Kerberos Policy Settings:", ""]
            
            # MaxTicketAge (TGT lifetime in hours) - Default/Recommended: 10
            max_ticket_age = kerberos_policy.get('MaxTicketAge', DEFAULT_KERBEROS_POLICY['MaxTicketAge'])
            policy_lines.append(f"  TGT Lifetime (MaxTicketAge): {max_ticket_age} hours")
            if max_ticket_age != 10:
                self.logger.finding(f"TGT lifetime is {max_ticket_age} hours (recommended: 10)")
                findings.append(f"TGT lifetime is {max_ticket_age} hours (recommended: 10)")
            else:
                self.logger.success(f"[+] TGT lifetime is {max_ticket_age} hours")
            
            # MaxRenewAge (TGT renewal in days) - Default/Recommended: 7
            max_renew_age = kerberos_policy.get('MaxRenewAge', DEFAULT_KERBEROS_POLICY['MaxRenewAge'])
            policy_lines.append(f"  TGT Renewal Lifetime (MaxRenewAge): {max_renew_age} days")
            if max_renew_age != 7:
                self.logger.finding(f"TGT renewal lifetime is {max_renew_age} days (recommended: 7)")
                findings.append(f"TGT renewal lifetime is {max_renew_age} days (recommended: 7)")
            else:
                self.logger.success(f"[+] TGT renewal lifetime is {max_renew_age} days")
            
            # MaxServiceAge (Service ticket lifetime in minutes) - Default/Recommended: 600
            max_service_age = kerberos_policy.get('MaxServiceAge', DEFAULT_KERBEROS_POLICY['MaxServiceAge'])
            policy_lines.append(f"  Service Ticket Lifetime (MaxServiceAge): {max_service_age} minutes")
            if max_service_age != 600:
                self.logger.finding(f"Service ticket lifetime is {max_service_age} minutes (recommended: 600)")
                findings.append(f"Service ticket lifetime is {max_service_age} minutes (recommended: 600)")
            else:
                self.logger.success(f"[+] Service ticket lifetime is {max_service_age} minutes")
            
            # MaxClockSkew (Clock skew tolerance in minutes) - Default/Recommended: 5
            max_clock_skew = kerberos_policy.get('MaxClockSkew', DEFAULT_KERBEROS_POLICY['MaxClockSkew'])
            policy_lines.append(f"  Clock Skew Tolerance (MaxClockSkew): {max_clock_skew} minutes")
            if max_clock_skew != 5:
                self.logger.warning(f"[!] Clock skew tolerance is {max_clock_skew} minutes (recommended: 5)")
                findings.append(f"Clock skew tolerance is {max_clock_skew} minutes (recommended: 5)")
            else:
                self.logger.success(f"[+] Clock skew tolerance is {max_clock_skew} minutes")
            
            # TicketValidateClient - Recommended: 1 (enabled)
            validate_client = kerberos_policy.get('TicketValidateClient', DEFAULT_KERBEROS_POLICY['TicketValidateClient'])
            policy_lines.append(f"  Validate Client (TicketValidateClient): {validate_client}")
            if validate_client != 1:
                self.logger.finding("Kerberos client validation is DISABLED")
                findings.append("Kerberos client validation is disabled")
            else:
                self.logger.success("[+] Kerberos client validation is enabled")
            
            # Write results
            policy_lines.append("")
            if findings:
                policy_lines.append("Findings:")
                policy_lines.extend([f"  - {f}" for f in findings])
            else:
                policy_lines.append("Findings: None - Kerberos policy is secure")
            
            filepath = self.output_paths['findings'] / 'kerberospolicy.txt'
            write_file('\n'.join(policy_lines), filepath, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Kerberos policy: {e}")
    
    def _parse_kerberos_policy(self, content: bytes) -> dict:
        """Parse Kerberos policy from GptTmpl.inf content."""
        policy = {}
        
        try:
            # Decode content (usually UTF-16 LE with BOM)
            try:
                text = content.decode('utf-16-le')
            except UnicodeDecodeError:
                try:
                    text = content.decode('utf-16')
                except UnicodeDecodeError:
                    text = content.decode('utf-8', errors='ignore')
            
            # Remove BOM if present
            if text.startswith('\ufeff'):
                text = text[1:]
            
            # Parse as INI file
            config = configparser.ConfigParser()
            config.read_string(text)
            
            # Look for Kerberos Policy section
            if 'Kerberos Policy' in config.sections():
                for key, value in config.items('Kerberos Policy'):
                    # Normalize key names (case-insensitive)
                    key_normalized = key.replace(' ', '')
                    for default_key in DEFAULT_KERBEROS_POLICY.keys():
                        if key_normalized.lower() == default_key.lower():
                            try:
                                policy[default_key] = int(value)
                            except ValueError:
                                policy[default_key] = value
                            break
            
        except Exception as e:
            self.logger.debug(f"Error parsing GptTmpl.inf: {e}")
        
        return policy
    
    def check_fine_grained_password_policy(self):
        """Check for fine-grained password policies (PSOs)."""
        self.logger.info("---Checking Fine-grained password policy---")
        
        try:
            all_users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'msDS-PSOApplied', 'userAccountControl']
            )
            
            users_with_pso = [u for u in all_users if u.get('msDS-PSOApplied')]
            filepath = self.output_paths['data'] / 'users_finegrainedpasswordpolicy.txt'
            
            if users_with_pso:
                count = len(users_with_pso)
                self.logger.finding(f"There are {count} users with fine-grained password policy")
                write_csv(users_with_pso, filepath)
                
                users_without_pso = [u for u in all_users if not u.get('msDS-PSOApplied')]
                
                if users_without_pso:
                    spray_list = [u.get('sAMAccountName', '') for u in users_without_pso if u.get('sAMAccountName')]
                    spray_file = self.output_paths['data'] / 'users_NO_finegrainedpasswordpolicy.txt'
                    write_lines(spray_list, spray_file)
                    self.logger.finding("If you don't want to lockout users, spray with this list!")
            else:
                self.logger.success("[+] There were no users with a fine-grained password policy")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking fine-grained password policy: {e}")
