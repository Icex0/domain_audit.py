"""Active Directory enumeration module."""

import csv
from typing import Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass

from ..utils.logger import get_logger
from ..utils.ldap import LDAPConnection, LDAPConfig
from ..utils.output import write_csv, write_lines
from ..core.exceptions import EnumerationError


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
        self.logger.section("GATHERING DATA")
        self.logger.info("Gathering data of all Users, Groups, Computerobjects, GPOs, OUs, DCs")
        
        # Get domain SID first (needed for privileged group enumeration)
        self.logger.log_verbose("Gathering domain SID")
        domain_sid = self.get_domain_sid()
        self.logger.info(f"Domain SID: {domain_sid}")
        
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
    
    def get_privileged_groups(self, domain_sid: str) -> Dict[str, Dict]:
        """
        Get well-known privileged groups by SID.
        
        Args:
            domain_sid: The domain SID
            
        Returns:
            Dictionary mapping group names to group data
        """
        self.logger.log_verbose("Resolving privileged group names from SIDs")
        
        # Build RIDs for well-known groups
        rid_map = {
            'Domain Admins': f"{domain_sid}-512",
            'Domain Users': f"{domain_sid}-513",
            'Domain Guests': f"{domain_sid}-514",
            'Domain Computers': f"{domain_sid}-515",
            'Domain Controllers': f"{domain_sid}-516",
            'Cert Publishers': f"{domain_sid}-517",
            'Schema Admins': f"{domain_sid}-518",
            'Enterprise Admins': f"{domain_sid}-519",
            'Group Policy Creator Owners': f"{domain_sid}-520",
            'Protected Users': f"{domain_sid}-525",
            'Key Admins': f"{domain_sid}-526",
        }
        
        groups = {}
        for name, sid in rid_map.items():
            result = self.ldap.query(
                search_base=self.base_dn,
                search_filter=f'(objectSid={sid})',
                attributes=['sAMAccountName', 'member']
            )
            if result:
                groups[name] = result[0]
        
        return groups
    
    def get_group_members(self, group_name: str) -> List[Dict]:
        """Get members of a specific group."""
        self.logger.log_verbose(f"Getting members of group: {group_name}")
        
        # First get the group DN
        groups = self.ldap.query(
            search_base=self.base_dn,
            search_filter=f'(&(objectClass=group)(sAMAccountName={group_name}))',
            attributes=['member', 'distinguishedName']
        )
        
        if not groups:
            return []
        
        members = []
        member_dns = groups[0].get('member', [])
        
        if isinstance(member_dns, str):
            member_dns = [member_dns]
        
        for member_dn in member_dns:
            if not member_dn:
                continue
                
            # Get member details
            member = self.ldap.query(
                search_base=member_dn,
                search_filter='(objectClass=*)',
                attributes=['sAMAccountName', 'objectClass']
            )
            
            if member:
                members.append(member[0])
        
        return members
    
    def get_admin_count_accounts(self) -> List[Dict]:
        """Get accounts with adminCount=1 (privileged accounts)."""
        self.logger.log_verbose("Finding accounts with adminCount=1")
        
        return self.ldap.query(
            search_base=self.base_dn,
            search_filter='(adminCount=1)',
            attributes=['sAMAccountName', 'memberOf']
        )
