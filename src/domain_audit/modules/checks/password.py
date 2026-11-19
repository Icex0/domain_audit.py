"""Password policy security checks."""

import io
from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv
from ...utils.gpttmpl import parse_gpttmpl_inf
from ...utils.dc import select_reachable_dc

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
            
            # DOMAIN_PASSWORD_STORE_CLEARTEXT (0x10, MS-SAMR): passwords set while
            # this is on are stored with reversible encryption in NTDS.dit and can be
            # recovered in cleartext (e.g. via DCSync / NTDS backup)
            if pwd_properties & 0x10:
                self.logger.finding("Domain password policy stores passwords using reversible encryption")
                findings.append("Passwords are stored using reversible encryption (pwdProperties 0x10)")
            else:
                self.logger.success("[+] Passwords are not stored using reversible encryption")

            lockout_threshold = policy.get('lockoutThreshold', 0)
            if lockout_threshold == 0:
                self.logger.finding("LockOutBadCount is 0, accounts won't be locked!")
                findings.append("Account lockout is disabled")
            elif lockout_threshold > 6:
                self.logger.finding(f"LockOutBadCount is {lockout_threshold} (> 6)")
                findings.append(f"Lockout threshold is too high ({lockout_threshold})")
            else:
                self.logger.success(f"[+] LockOutBadCount is {lockout_threshold}")
            
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

            # Only report as a finding if the policy is actually weak
            if findings:
                filepath = self.output_paths['findings'] / 'passwordpolicy.txt'
            else:
                filepath = self.output_paths['checks'] / 'passwordpolicy.txt'
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
                dc_hostname = select_reachable_dc(dcs, fallback=self.server, logger=self.logger)
            
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
            
            # Lifetimes: only values longer than Microsoft's default are weaker, a
            # shorter lifetime is stricter. For the three ticket lifetimes, 0 means
            # "never expires" (Microsoft Kerberos Policy docs), so 0 is weak too.
            # (key, label, unit, recommended max, 0 means unlimited)
            lifetime_settings = [
                ('MaxTicketAge', 'TGT lifetime', 'hours', 10, True),
                ('MaxRenewAge', 'TGT renewal lifetime', 'days', 7, True),
                ('MaxServiceAge', 'Service ticket lifetime', 'minutes', 600, True),
                ('MaxClockSkew', 'Clock skew tolerance', 'minutes', 5, False),
            ]
            for key, label, unit, recommended, zero_is_unlimited in lifetime_settings:
                value = kerberos_policy.get(key, DEFAULT_KERBEROS_POLICY[key])
                policy_lines.append(f"  {label} ({key}): {value} {unit}")
                if not isinstance(value, int):
                    self.logger.warning(f"[!] {label} has an unexpected value: {value}")
                    continue
                if zero_is_unlimited and value == 0:
                    message = f"{label} is 0 (never expires) - recommended: {recommended} {unit} or less"
                elif value > recommended:
                    message = f"{label} is {value} {unit} (recommended: {recommended} or less)"
                else:
                    self.logger.success(f"[+] {label} is {value} {unit}")
                    continue
                self.logger.finding(message)
                findings.append(message)
            
            # TicketValidateClient - Recommended: 1 (enabled)
            validate_client = kerberos_policy.get('TicketValidateClient', DEFAULT_KERBEROS_POLICY['TicketValidateClient'])
            policy_lines.append(f"  Validate Client (TicketValidateClient): {validate_client}")
            if validate_client != 1:
                self.logger.finding("Kerberos client validation is DISABLED")
                findings.append("Kerberos client validation is disabled")
            else:
                self.logger.success("[+] Kerberos client validation is enabled")
            
            # Write results - only to findings if there are actual findings
            policy_lines.append("")
            if findings:
                policy_lines.append("Findings:")
                policy_lines.extend([f"  - {f}" for f in findings])
                filepath = self.output_paths['findings'] / 'kerberospolicy.txt'
                write_file('\n'.join(policy_lines), filepath, self.logger)
            else:
                policy_lines.append("Kerberos policy is secure (matches Microsoft recommendations)")
                filepath = self.output_paths['checks'] / 'kerberospolicy.txt'
                write_file('\n'.join(policy_lines), filepath, self.logger)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Kerberos policy: {e}")
    
    def _parse_kerberos_policy(self, content: bytes) -> dict:
        """Parse Kerberos policy from GptTmpl.inf content."""
        policy = {}
        parsed = parse_gpttmpl_inf(content)
        
        # configparser lowercases keys, so we need case-insensitive matching
        # to map back to the canonical key names in DEFAULT_KERBEROS_POLICY
        kerberos_section = parsed.get('Kerberos Policy', parsed.get('kerberos policy', {}))
        
        for key, value in kerberos_section.items():
            key_normalized = key.replace(' ', '')
            for default_key in DEFAULT_KERBEROS_POLICY.keys():
                if key_normalized.lower() == default_key.lower():
                    try:
                        policy[default_key] = int(value)
                    except ValueError:
                        policy[default_key] = value
                    break
        
        return policy
    
    def check_fine_grained_password_policy(self):
        """Check for fine-grained password policies (PSOs)."""
        self.logger.info("---Checking Fine-grained password policy---")
        
        try:
            # msDS-ResultantPSO is the effective PSO (also when applied via a group);
            # msDS-PSOApplied only lists PSOs targeted at the object directly.
            # Verified in a lab: a normal domain user can read msDS-ResultantPSO of
            # other users in a paged subtree search, but can't read the PSO objects
            # (so their lockout threshold is unknown).
            all_users = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'msDS-ResultantPSO']
            )
            
            users_with_pso = []
            users_without_pso = []
            for user in all_users:
                pso = user.get('msDS-ResultantPSO')
                if isinstance(pso, list):
                    pso = pso[0] if pso else None
                if pso:
                    users_with_pso.append({'sAMAccountName': user.get('sAMAccountName', ''), 'msDS-ResultantPSO': pso})
                else:
                    users_without_pso.append(user)
            filepath = self.output_paths['data'] / 'users_finegrainedpasswordpolicy.txt'
            
            if users_with_pso:
                count = len(users_with_pso)
                pso_names = sorted({u['msDS-ResultantPSO'].split(',')[0].replace('CN=', '') for u in users_with_pso})
                self.logger.finding(f"There are {count} users with a fine-grained password policy ({', '.join(pso_names)})")
                write_csv(users_with_pso, filepath)
                
                if users_without_pso:
                    # Users without a PSO follow the domain password policy. Users with a
                    # PSO are left out: their lockout threshold may be stricter and the
                    # PSO itself usually isn't readable for a normal user.
                    spray_list = [u.get('sAMAccountName', '') for u in users_without_pso if u.get('sAMAccountName')]
                    spray_file = self.output_paths['data'] / 'users_NO_finegrainedpasswordpolicy.txt'
                    write_lines(spray_list, spray_file)
                    self.logger.finding("If you don't want to lockout users, spray with this list (domain lockout policy applies)!")
            else:
                self.logger.success("[+] There were no users with a fine-grained password policy")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking fine-grained password policy: {e}")
