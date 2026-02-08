"""Azure AD Connect checks."""

from datetime import datetime, timedelta
from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_file, write_lines


class AzureChecker:
    """Checks for Azure AD Connect configuration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_azure_ad_connect(self):
        """Check for Azure AD Connect installation and configuration."""
        self.logger.info("---Checking for Azure AD Connect---")
        
        findings = []
        
        # Check for Azure AD Connect service accounts
        azure_accounts = self._check_azure_accounts()
        if azure_accounts:
            findings.extend(azure_accounts)
        
        # Check for MSOL accounts
        msol_accounts = self._check_msol_accounts()
        if msol_accounts:
            findings.extend(msol_accounts)
        
        # Check for AADConnect group membership
        sync_groups = self._check_sync_groups()
        if sync_groups:
            findings.extend(sync_groups)
        
        if findings:
            self.logger.finding("Azure AD Connect may be installed - check for vulnerabilities")
            write_csv(findings, self.output_paths['findings'] / 'azure_ad_connect.txt')
        else:
            self.logger.success("[+] Azure AD Connect not detected")
    
    def _check_azure_accounts(self) -> List[Dict]:
        """Check for Azure AD Connect related service accounts."""
        accounts = []
        
        try:
            # Search for accounts with Azure-related SPNs or names
            azure_patterns = [
                '(servicePrincipalName=*Azure*)',
                '(servicePrincipalName=*AADConnect*)',
                '(sAMAccountName=*azure*)',
                '(sAMAccountName=*AADConnect*)',
                '(sAMAccountName=*sync_*)',
                '(displayName=*Azure AD Connect*)'
            ]
            
            for pattern in azure_patterns:
                try:
                    results = self.ldap.query(
                        search_base=self.base_dn,
                        search_filter=f'(&(objectClass=user){pattern})',
                        attributes=['sAMAccountName', 'servicePrincipalName', 'memberOf', 'description']
                    )
                    
                    for result in results:
                        accounts.append({
                            'type': 'Azure Account',
                            'username': result.get('sAMAccountName', ''),
                            'spn': result.get('servicePrincipalName', ''),
                            'description': result.get('description', '')
                        })
                        self.logger.warning(f"[!] Found Azure-related account: {result.get('sAMAccountName', '')}")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking Azure accounts: {e}")
        
        return accounts
    
    def _check_msol_accounts(self) -> List[Dict]:
        """Check for MSOL (Microsoft Online) service accounts."""
        accounts = []
        
        try:
            # MSOL accounts are created by Azure AD Connect
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=MSOL_*)',
                attributes=['sAMAccountName', 'displayName', 'description', 'memberOf']
            )
            
            for result in results:
                username = result.get('sAMAccountName', '')
                accounts.append({
                    'type': 'MSOL Account',
                    'username': username,
                    'display_name': result.get('displayName', ''),
                    'description': result.get('description', '')
                })
                self.logger.warning(f"[!] Found MSOL account: {username}")
                self.logger.finding("MSOL accounts have DCSync privileges - extract credentials!")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking MSOL accounts: {e}")
        
        return accounts
    
    def _check_sync_groups(self) -> List[Dict]:
        """Check for Azure AD Connect synchronization groups."""
        groups = []
        
        sync_groups = [
            "ADSyncAdmins",
            "ADSyncOperators", 
            "ADSyncBrowse",
            "ADSyncPasswordSet",
            "Azure AD Connect Admins"
        ]
        
        try:
            for group_name in sync_groups:
                try:
                    results = self.ldap.query(
                        search_base=self.base_dn,
                        search_filter=f'(&(objectClass=group)(cn={group_name}))',
                        attributes=['cn', 'member', 'description']
                    )
                    
                    for result in results:
                        group_cn = result.get('cn', '')
                        members = result.get('member', [])
                        member_count = len(members) if isinstance(members, list) else 1 if members else 0
                        
                        groups.append({
                            'type': 'Azure Sync Group',
                            'group_name': group_cn,
                            'member_count': member_count,
                            'description': result.get('description', '')
                        })
                        self.logger.warning(f"[!] Found Azure AD Connect group: {group_cn} ({member_count} members)")
                        
                except Exception:
                    continue
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking sync groups: {e}")
        
        return groups
    
    def check_azure_ad_connect_server(self):
        """Check which server hosts Azure AD Connect."""
        self.logger.info("---Checking for Azure AD Connect server---")
        
        try:
            # Check for computers with MSOL service accounts
            # The MSOL account name format is: MSOL_<installation_id>
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=MSOL_*)',
                attributes=['sAMAccountName', 'description']
            )
            
            server_found = False
            
            for result in results:
                # MSOL account description often contains the server name
                description = result.get('description', '')
                if description and 'Server:' in description:
                    server_name = description.split('Server:')[1].strip().split()[0]
                    self.logger.finding(f"Azure AD Connect installed on: {server_name}")
                    server_found = True
                    
                    write_file(
                        f"Azure AD Connect Server: {server_name}\n"
                        f"Service Account: {result.get('sAMAccountName', '')}\n\n"
                        "Check if you have access to this server to extract credentials.",
                        self.output_paths['findings'] / 'azure_ad_connect_server.txt',
                        self.logger
                    )
            
            if not server_found:
                self.logger.success("[+] No Azure AD Connect server detected")
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking Azure AD Connect server: {e}")
    
    def check_azureadssoacc_security(self):
        """Check AZUREADSSOACC computer account security.
        
        Per Microsoft recommendations:
        - Kerberos delegation must be disabled on the account
        - No other account should have delegation permissions to AZUREADSSOACC
        - Kerberos decryption key should be renewed at least every 30 days
        
        Reference: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works
        """
        self.logger.info("---Checking AZUREADSSOACC security---")
        
        try:
            # Search for AZUREADSSOACC computer account
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(sAMAccountName=AZUREADSSOACC$))',
                attributes=[
                    'sAMAccountName', 'userAccountControl', 'pwdLastSet',
                    'msDS-AllowedToDelegateTo', 'msDS-AllowedToActOnBehalfOfOtherIdentity'
                ]
            )
            
            if not results:
                self.logger.info("[*] AZUREADSSOACC computer account not found (Seamless SSO not configured)")
                return
            
            account = results[0]
            findings = []
            account_name = account.get('sAMAccountName', 'AZUREADSSOACC$')
            
            self.logger.warning(f"[!] Found {account_name} - checking security configuration")
            
            # Check 1: Unconstrained Kerberos delegation disabled (TRUSTED_FOR_DELEGATION = 524288)
            uac = account.get('userAccountControl', 0)
            if isinstance(uac, str):
                uac = int(uac)
            
            if uac & 524288:  # TRUSTED_FOR_DELEGATION
                self.logger.finding(f"AZUREADSSOACC has Kerberos delegation ENABLED (vulnerable!)")
                findings.append("CRITICAL: Kerberos delegation is ENABLED on AZUREADSSOACC - should be disabled")
            else:
                self.logger.success("[+] AZUREADSSOACC has Kerberos delegation disabled")
            
            # Check 2: Constrained delegation (msDS-AllowedToDelegateTo)
            allowed_to_delegate = account.get('msDS-AllowedToDelegateTo')
            if allowed_to_delegate:
                self.logger.finding("AZUREADSSOACC has constrained delegation configured")
                if isinstance(allowed_to_delegate, list):
                    for target in allowed_to_delegate:
                        findings.append(f"CRITICAL: Constrained delegation to: {target}")
                else:
                    findings.append(f"CRITICAL: Constrained delegation to: {allowed_to_delegate}")
            else:
                self.logger.success("[+] AZUREADSSOACC has no constrained delegation")
            
            # Check 3: Resource-based constrained delegation (msDS-AllowedToActOnBehalfOfOtherIdentity)
            rbcd = account.get('msDS-AllowedToActOnBehalfOfOtherIdentity')
            if rbcd:
                self.logger.finding("AZUREADSSOACC has RBCD configured - other accounts can delegate to it!")
                findings.append("CRITICAL: RBCD is configured - other accounts have delegation permissions to AZUREADSSOACC")
            else:
                self.logger.success("[+] No RBCD configured on AZUREADSSOACC")
            
            # Check 4: Kerberos decryption key age (derived from computer account password)
            # Microsoft recommends renewing at least every 30 days via pwdLastSet
            pwd_last_set = account.get('pwdLastSet')
            if pwd_last_set:
                try:
                    # pwdLastSet is Windows FILETIME (100-nanosecond intervals since 1601-01-01)
                    if isinstance(pwd_last_set, str):
                        pwd_last_set = int(pwd_last_set)
                    
                    if pwd_last_set > 0:
                        # Convert Windows FILETIME to datetime
                        # FILETIME epoch is 1601-01-01, Unix epoch is 1970-01-01
                        # Difference is 116444736000000000 (100-nanosecond intervals)
                        windows_epoch_diff = 116444736000000000
                        unix_timestamp = (pwd_last_set - windows_epoch_diff) / 10000000
                        pwd_date = datetime.fromtimestamp(unix_timestamp)
                        
                        age_days = (datetime.now() - pwd_date).days
                        
                        if age_days > 30:
                            self.logger.finding(f"AZUREADSSOACC Kerberos key is {age_days} days old (should be renewed every 30 days)")
                            findings.append(f"WARNING: Kerberos decryption key is {age_days} days old - Microsoft recommends renewal every 30 days")
                            findings.append(f"Last password change: {pwd_date.strftime('%Y-%m-%d')}")
                        else:
                            self.logger.success(f"[+] AZUREADSSOACC Kerberos key is {age_days} days old (within 30-day window)")
                    else:
                        self.logger.warning("[!] AZUREADSSOACC password never set or set to never expire")
                        findings.append("WARNING: Password appears to never have been set")
                        
                except Exception as e:
                    self.logger.debug(f"Could not parse pwdLastSet: {e}")
            
            # Check 5: Check if any other accounts have delegation to AZUREADSSOACC
            self._check_delegation_to_azureadssoacc(findings)
            
            # Write findings
            if findings:
                write_lines(
                    ["AZUREADSSOACC Security Issues", "=" * 40, ""] + findings + 
                    ["", "Reference: https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sso-how-it-works"],
                    self.output_paths['findings'] / 'azureadssoacc_security.txt'
                )
            else:
                self.logger.success("[+] AZUREADSSOACC security configuration is correct")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking AZUREADSSOACC security: {e}")
    
    def _check_delegation_to_azureadssoacc(self, findings: List[str]):
        """Check if any accounts have constrained delegation permissions to AZUREADSSOACC."""
        try:
            # Search for accounts with constrained delegation to AZUREADSSOACC
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(msDS-AllowedToDelegateTo=*AZUREADSSOACC*)',
                attributes=['sAMAccountName', 'msDS-AllowedToDelegateTo', 'objectClass']
            )
            
            if results:
                self.logger.finding(f"{len(results)} accounts have constrained delegation to AZUREADSSOACC")
                for result in results:
                    account_name = result.get('sAMAccountName', 'Unknown')
                    findings.append(f"CRITICAL: {account_name} has constrained delegation permissions to AZUREADSSOACC")
            else:
                self.logger.success("[+] No accounts have constrained delegation to AZUREADSSOACC")
                
        except Exception as e:
            self.logger.debug(f"Error checking delegation to AZUREADSSOACC: {e}")
