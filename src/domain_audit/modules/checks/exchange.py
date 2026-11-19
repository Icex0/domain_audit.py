"""Exchange Server security checks."""

from typing import Dict, List, Optional
from pathlib import Path
from datetime import datetime, timedelta, timezone

import ldap3
from ldap3.utils.conv import escape_filter_chars

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_csv, write_lines
from ...utils.acl import SD_FLAGS_DACL, WRITE_DAC, WRITE_OWNER, right_decisions


class ExchangeChecker:
    """Checks for Exchange Server configuration and permissions."""
    
    # Exchange specific group names
    EXCHANGE_GROUPS = [
        "Exchange Trusted Subsystem",
        "Exchange Windows Permissions", 
        "Organization Management"
    ]
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
    
    def check_exchange(self):
        """Run all Exchange security checks."""
        self._check_exchange_groups()

    def _get_group_dn(self, cn: str) -> Optional[str]:
        """Return the DN of a group by cn, or None if it doesn't exist."""
        groups = self.ldap.query(
            search_base=self.base_dn,
            search_filter=f'(&(objectClass=group)(cn={escape_filter_chars(cn)}))',
            attributes=['distinguishedName']
        )
        return groups[0].get('distinguishedName') if groups else None

    def _get_nested_members(self, group_cn: str, object_filter: str, attributes: List[str]) -> List[Dict]:
        """Return direct and nested members of a group matching object_filter.

        AD doesn't support wildcards on DN-valued attributes like memberOf, so the
        group's DN is resolved first and matched with LDAP_MATCHING_RULE_IN_CHAIN.
        """
        group_dn = self._get_group_dn(group_cn)
        if not group_dn:
            return []
        return self.ldap.query(
            search_base=self.base_dn,
            search_filter=f'(&{object_filter}(memberOf:1.2.840.113556.1.4.1941:={escape_filter_chars(group_dn)}))',
            attributes=attributes
        )

    @staticmethod
    def _to_datetime(value) -> Optional[datetime]:
        """Convert lastLogonTimestamp (datetime from ldap3, or raw FILETIME) to aware UTC datetime."""
        if isinstance(value, list):
            value = value[0] if value else None
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        try:
            filetime = int(value)
        except (TypeError, ValueError):
            return None
        if filetime <= 0:
            return None
        return datetime.fromtimestamp(filetime / 10_000_000 - 11644473600, tz=timezone.utc)
    
    def _check_exchange_groups(self):
        """Check for Exchange groups and enumerate memberships."""
        self.logger.info("---Checking if Exchange is used within the domain---")
        
        try:
            # Check for default Exchange groups
            exchange_groups = []
            for group_name in self.EXCHANGE_GROUPS:
                groups = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter=f'(&(objectClass=group)(cn={group_name}))',
                    attributes=['cn', 'distinguishedName', 'member']
                )
                if groups:
                    exchange_groups.extend(groups)
            
            if not exchange_groups:
                self.logger.success("[+] No default Exchange groups discovered")
                return
            
            self.logger.info("[+] Default Exchange groups exist")
            write_csv(exchange_groups, self.output_paths['data'] / 'Exchange_groups.txt')
            
            # Check for Exchange servers via Exchange Trusted Subsystem members
            self._check_exchange_servers()
            
            # Check Exchange Windows Permissions membership
            self._check_exchange_permissions_group()
            
            # Check Organization Management membership  
            self._check_organization_management()
            
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange groups: {e}")
    
    def _check_exchange_servers(self):
        """Check for Exchange servers in Exchange Trusted Subsystem group."""
        self.logger.info("---Checking for Exchange servers---")
        
        try:
            # Check for computer objects in Exchange Trusted Subsystem
            computers = self._get_nested_members(
                'Exchange Trusted Subsystem', '(objectClass=computer)',
                ['sAMAccountName', 'distinguishedName', 'lastLogonTimestamp']
            )
            
            exchange_servers = []
            
            # Get computers from memberOf
            for comp in computers:
                exchange_servers.append(comp)
            
            # Also check for Exchange servers by name patterns
            exchange_name_patterns = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(|(name=*EXCH*)(name=*MAIL*)(name=*EXCHANGE*)))',
                attributes=['sAMAccountName', 'distinguishedName', 'lastLogonTimestamp']
            )
            
            for comp in exchange_name_patterns:
                # Avoid duplicates
                if not any(c.get('sAMAccountName') == comp.get('sAMAccountName') for c in exchange_servers):
                    exchange_servers.append(comp)
            
            if exchange_servers:
                self.logger.info(f"[*] Discovered {len(exchange_servers)} potential Exchange servers")
                write_csv(exchange_servers, self.output_paths['data'] / 'Exchange_servers.txt')
                
                # Check for recent logons (within last 31 days)
                # lastLogonTimestamp replicates with up to ~14 days lag, so 31 days is a safe window
                cutoff = datetime.now(timezone.utc) - timedelta(days=31)
                recent_logons = []

                for server in exchange_servers:
                    last_logon = self._to_datetime(server.get('lastLogonTimestamp'))
                    if last_logon and last_logon > cutoff:
                        recent_logons.append(server)
                
                if recent_logons:
                    self.logger.info(f"[*] There has been a logon on {len(recent_logons)} Exchange server(s) in the last 30 days")
                    self.logger.info("[*] Manually check for access/open mailboxes with OWA or Mailsniper")
                else:
                    self.logger.info("[*] No logon within the last 31 days, might be old servers")
            else:
                self.logger.success("[+] Exchange Trusted Subsystem has no computer memberships")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange servers: {e}")
    
    def _check_exchange_permissions_group(self):
        """Check whether Exchange groups can modify the domain object's DACL.

        Before the 2019 Exchange cumulative updates, the "Exchange Windows
        Permissions" group had an ACE granting WriteDACL on the domain root that
        also applied to the domain object itself, so members (including Exchange
        servers via Exchange Trusted Subsystem) could grant themselves DCSync
        (PrivExchange). The fix (KB 4490059, after /PrepareAD) adds the
        Inherit-Only flag to that ACE; it doesn't remove it. So this reads the
        domain object's DACL and evaluates the effective rights instead of
        judging by group membership.
        """
        self.logger.info("---Checking Exchange permissions on the domain object---")
        
        try:
            groups = {}
            for cn in ('Exchange Windows Permissions', 'Exchange Trusted Subsystem'):
                result = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter=f'(&(objectClass=group)(cn={escape_filter_chars(cn)}))',
                    attributes=['objectSid']
                )
                if result and result[0].get('objectSid'):
                    groups[str(result[0]['objectSid'])] = cn
            
            members = self._get_nested_members(
                'Exchange Windows Permissions', '(objectCategory=person)(objectClass=user)',
                ['sAMAccountName', 'distinguishedName']
            )
            if members:
                write_csv(members, self.output_paths['data'] / 'Exchange_memberships_ExchangeWindowsPermissions.txt')
            
            if not groups:
                self.logger.info("[*] Exchange Windows Permissions / Exchange Trusted Subsystem groups not found")
                return
            
            self.ldap.connection.search(
                search_base=self.base_dn,
                search_filter='(objectClass=domainDNS)',
                search_scope=ldap3.BASE,
                attributes=['nTSecurityDescriptor'],
                controls=SD_FLAGS_DACL
            )
            raw = self.ldap.connection.entries[0]['nTSecurityDescriptor'].raw_values if self.ldap.connection.entries else []
            if not raw:
                self.logger.warning("[!] Could not read the domain object's DACL - verify Exchange WriteDACL manually")
                return
            
            decisions = right_decisions(raw[0], WRITE_DAC | WRITE_OWNER, sids=groups.keys())
            dangerous = [groups[sid] for sid, allowed in decisions.items() if allowed]
            
            if dangerous:
                self.logger.finding(
                    f"{', '.join(dangerous)} can modify the domain object's DACL (WriteDACL/WriteOwner) - "
                    "members and Exchange servers can grant themselves DCSync (PrivExchange). "
                    "Apply the 2019+ Exchange CU and run /PrepareAD"
                )
                lines = [f"Group with WriteDACL/WriteOwner on {self.base_dn}: {g}" for g in dangerous]
                if members:
                    lines.append("")
                    lines.append("User members of Exchange Windows Permissions (nested included):")
                    lines.extend(f"  {m.get('sAMAccountName', '')}" for m in members)
                write_lines(lines, self.output_paths['findings'] / 'Exchange_WriteDACL_domain_object.txt')
            else:
                self.logger.success(
                    "[+] Exchange groups can't modify the domain object's DACL (ACE absent or Inherit-Only)"
                )
                if members:
                    self.logger.info(f"[*] {len(members)} user(s) in Exchange Windows Permissions (saved to data)")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Exchange Windows Permissions: {e}")
    
    def _check_organization_management(self):
        """Check Organization Management group membership.
        
        Organization Management has full control over the Exchange organization
        and can manage Exchange Windows Permissions membership, providing an
        indirect path to domain compromise via WriteDACL escalation.
        """
        self.logger.info("---Checking for Organization Management membership---")
        
        try:
            # Get members of Organization Management
            members = self._get_nested_members(
                'Organization Management', '(objectCategory=person)(objectClass=user)',
                ['sAMAccountName', 'distinguishedName', 'memberOf']
            )
            
            if members:
                self.logger.finding(
                    f"{len(members)} user(s) in Organization Management - can manage Exchange group memberships and escalate to domain admin"
                )
                write_csv(
                    members,
                    self.output_paths['data'] / 'Exchange_memberships_OrganizationManagement.txt'
                )
            else:
                self.logger.success("[+] There are no users in Organization Management")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Organization Management: {e}")
