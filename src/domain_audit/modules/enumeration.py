"""Active Directory enumeration module."""

import csv
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection, LDAPConfig
from ..utils.output import write_csv, write_lines
from ..core.exceptions import EnumerationError
from ldap3.utils.conv import escape_filter_chars


@dataclass
class DomainData:
    """Container for domain enumeration results."""
    users: List[Dict]
    groups: List[Dict]
    computers: List[Dict]
    gpos: List[Dict]
    ous: List[Dict]
    domain_controllers: List[Dict]
    domain_sid: str


class ADEnumerator:
    """Handles Active Directory enumeration."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def enumerate_all(self) -> DomainData:
        """Run all enumeration tasks."""
        # Get domain SID first (needed for privileged group enumeration)
        self.logger.log_verbose("Gathering domain SID")
        domain_sid = self.get_domain_sid()
        
        # Enumerate all objects
        users = self.enumerate_users()
        groups = self.enumerate_groups()
        computers = self.enumerate_computers()
        gpos = self.enumerate_gpos()
        ous = self.enumerate_ous()
        dcs = self.enumerate_domain_controllers()
        
        return DomainData(
            users=users,
            groups=groups,
            computers=computers,
            gpos=gpos,
            ous=ous,
            domain_controllers=dcs,
            domain_sid=domain_sid
        )
    
    def get_domain_sid(self) -> str:
        """Get the domain SID."""
        return self.ldap.get_domain_sid()
    
    def enumerate_users(self) -> List[Dict]:
        """Enumerate all users."""
        self.logger.log_verbose("Gathering data of all Users")
        
        attributes = [
            'sAMAccountName', 'description', 'mail', 'servicePrincipalName',
            'msDS-AllowedToDelegateTo', 'userAccountControl', 'lastLogon',
            'pwdLastSet', 'memberOf', 'adminCount'
        ]
        
        users = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(&(objectClass=user)(objectCategory=person))',
            attributes=attributes
        )
        
        # Save to CSV
        if users:
            csv_path = self.output_paths['data'] / 'data_users.csv'
            write_csv(users, csv_path)
        
        return users
    
    def enumerate_groups(self) -> List[Dict]:
        """Enumerate all groups."""
        self.logger.log_verbose("Gathering data of all Groups")
        
        attributes = ['sAMAccountName', 'description', 'groupType', 'member', 'adminCount']
        
        groups = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=group)',
            attributes=attributes
        )
        
        if groups:
            csv_path = self.output_paths['data'] / 'data_groups.csv'
            write_csv(groups, csv_path)
        
        return groups
    
    def enumerate_computers(self) -> List[Dict]:
        """Enumerate all computers."""
        self.logger.log_verbose("Gathering data of all Computerobjects")
        
        attributes = ['dNSHostName', 'sAMAccountName', 'operatingSystem', 
                     'operatingSystemVersion', 'lastLogon', 'userAccountControl']
        
        computers = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=computer)',
            attributes=attributes
        )
        
        if computers:
            csv_path = self.output_paths['data'] / 'data_computers.csv'
            write_csv(computers, csv_path)
        
        return computers
    
    def enumerate_gpos(self) -> List[Dict]:
        """Enumerate all GPOs."""
        self.logger.log_verbose("Gathering data of all GPOs")
        
        attributes = ['displayName', 'gPCFileSysPath', 'versionNumber']
        
        gpos = self.ldap.query(
            search_base=f"CN=Policies,CN=System,{self.base_dn}",
            search_filter='(objectClass=groupPolicyContainer)',
            attributes=attributes
        )
        
        if gpos:
            csv_path = self.output_paths['data'] / 'data_gpo.csv'
            write_csv(gpos, csv_path)
        
        return gpos
    
    def enumerate_ous(self) -> List[Dict]:
        """Enumerate all OUs."""
        self.logger.log_verbose("Gathering data of all OUs")
        
        attributes = ['name', 'description']
        
        ous = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(objectClass=organizationalUnit)',
            attributes=attributes
        )
        
        if ous:
            csv_path = self.output_paths['data'] / 'data_ou.csv'
            write_csv(ous, csv_path)
        
        return ous
    
    def enumerate_domain_controllers(self) -> List[Dict]:
        """Enumerate domain controllers."""
        self.logger.log_verbose("Gathering data of all domain controllers")
        
        attributes = ['dNSHostName', 'sAMAccountName', 'operatingSystem']
        
        dcs = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
            attributes=attributes
        )
        
        if dcs:
            csv_path = self.output_paths['data'] / 'data_domaincontrollers.csv'
            write_csv(dcs, csv_path)
        
        return dcs
    

    def get_privileged_user_members(self, domain_sid: str, rid: int) -> Optional[List[str]]:
        """Return sAMAccountNames of all users in a privileged group (by RID),
        including nested members and users with it as primary group.

        Returns None if the group doesn't exist in this domain.
        """
        group_result = self.ldap.query(
            search_base=self.base_dn,
            search_filter=f'(objectSid={domain_sid}-{rid})',
            attributes=['distinguishedName']
        )
        if not group_result or not group_result[0].get('distinguishedName'):
            return None
        group_dn = escape_filter_chars(group_result[0]['distinguishedName'])
        # memberOf with LDAP_MATCHING_RULE_IN_CHAIN resolves nested groups;
        # primary group membership (primaryGroupID) isn't stored in memberOf.
        members = self.ldap.query(
            search_base=self.base_dn,
            search_filter=(
                f'(&(objectCategory=person)(objectClass=user)'
                f'(|(memberOf:1.2.840.113556.1.4.1941:={group_dn})(primaryGroupID={rid})))'
            ),
            attributes=['sAMAccountName']
        )
        return sorted({m['sAMAccountName'] for m in members if m.get('sAMAccountName')}, key=str.lower)

    def enumerate_privileged_group_members(self, domain_sid: str) -> dict:
        """Enumerate effective user members (direct and nested) of Domain Admins
        and Enterprise Admins and write them to list_<group>.txt.
        
        Returns:
            Dict mapping group name to member count
        """
        self.logger.log_verbose("Enumerating Domain Admins and Enterprise Admins members")
        member_counts = {}
        
        for group_name, rid in (('Domain Admins', 512), ('Enterprise Admins', 519)):
            try:
                usernames = self.get_privileged_user_members(domain_sid, rid)
                if usernames is None:
                    self.logger.warning(f"[!] Could not find {group_name} group")
                    continue
                safe_name = group_name.replace(' ', '').lower()
                write_lines(usernames, self.output_paths['data'] / f'list_{safe_name}.txt')
                member_counts[group_name] = len(usernames)
            except Exception as e:
                self.logger.error(f"[-] Error enumerating {group_name}: {e}")
                member_counts[group_name] = 0
        
        return member_counts
