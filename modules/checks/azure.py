"""Azure AD Connect checks."""

from typing import Dict, List
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_file


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
