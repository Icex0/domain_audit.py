"""Azure AD Connect checks."""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_file, write_lines


_CONNECT_SERVER_PATTERNS = [
    r"\brunning\s+on\s+computer\s+([A-Za-z0-9][A-Za-z0-9._-]*)",
    r"\bserver\s*:\s*([A-Za-z0-9][A-Za-z0-9._-]*)",
]
_CONNECT_SERVER_TRAILING_PUNCTUATION = ".,;:)]}"


def _extract_connect_server_reference(description: str) -> Optional[str]:
    if not isinstance(description, str) or not description:
        return None

    for pattern in _CONNECT_SERVER_PATTERNS:
        match = re.search(pattern, description, re.IGNORECASE)
        if match:
            return match.group(1).rstrip(_CONNECT_SERVER_TRAILING_PUNCTUATION)

    return None


def _format_connect_server_references(references: List[Dict[str, str]]) -> str:
    sections = []
    for ref in references:
        sections.append(
            "\n".join([
                f"Microsoft Entra Connect Server Reference: {ref['server']}",
                f"AD DS Connector Account: {ref['account']}",
                f"Description: {ref['description']}",
                "",
                "Evidence scope:",
                (
                    "The LDAP account description references this server as the computer "
                    "associated with the Connect installation. This does not confirm that "
                    "the ADSync service is currently installed, running, or synchronizing "
                    "successfully."
                ),
            ])
        )

    return "\n\n".join(sections) + "\n"


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
                self.logger.warning("[!] MSOL accounts have DCSync privileges by design (expected) - high-value target if the AAD Connect server is compromised")
                
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
        """Check MSOL account descriptions for Microsoft Entra Connect server references."""
        self.logger.info("---Checking for Microsoft Entra Connect server reference---")
        
        try:
            # The MSOL account name format is usually MSOL_<installation_id>.
            # Custom installations may use an administrator-created connector account.
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=MSOL_*)',
                attributes=['sAMAccountName', 'description']
            )

            if not results:
                self.logger.info("[*] No MSOL-prefixed AD DS Connector accounts found")
                self.logger.info("[*] Custom Microsoft Entra Connect installations may use a connector account without an MSOL_ prefix")
                return

            references = []
            seen_servers = set()
            for result in results:
                description = result.get('description', '')
                server_name = _extract_connect_server_reference(description)
                if not server_name:
                    continue

                server_key = server_name.lower()
                if server_key in seen_servers:
                    continue

                seen_servers.add(server_key)
                references.append({
                    'server': server_name,
                    'account': result.get('sAMAccountName', '') or 'Unknown',
                    'description': description,
                })
                self.logger.warning(f"[!] Microsoft Entra Connect server reference found: {server_name}")

            if references:
                write_file(
                    _format_connect_server_references(references),
                    self.output_paths['findings'] / 'azure_ad_connect_server.txt',
                    self.logger
                )
            else:
                self.logger.info("[*] No Microsoft Entra Connect server reference could be extracted from MSOL account descriptions")
                self.logger.info("[*] Custom Microsoft Entra Connect installations may use a connector account without an MSOL_ prefix")
                    
        except Exception as e:
            self.logger.error(f"[-] Error checking Microsoft Entra Connect server reference: {e}")
    
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
