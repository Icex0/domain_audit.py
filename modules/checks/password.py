"""Password policy security checks."""

from typing import Dict
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_file, write_lines, write_csv


class PasswordChecker:
    """Checks related to password policies and Kerberos settings."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
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
        """Check Kerberos policy settings."""
        self.logger.info("---Checking password policy Kerberos---")
        
        try:
            results = self.ldap.query(
                search_base=f"CN=Policies,CN=System,{self.base_dn}",
                search_filter='(objectClass=groupPolicyContainer)',
                attributes=['displayName', 'gPCFileSysPath']
            )
            
            self.logger.info("[+] Kerberos policy check requires SYSVOL access (Phase 8)")
            
        except Exception as e:
            self.logger.error(f"[-] Error checking Kerberos policy: {e}")
    
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
