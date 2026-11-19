"""Resolve (nested) members of privileged groups - one definition of "admin".

Admins = direct or nested members of Administrators (S-1-5-32-544), Domain
Admins (RID 512) and Enterprise Admins (RID 519), plus accounts that have one
of those as primary group (primaryGroupID isn't reflected in memberOf).
"""

from typing import Dict, List, Optional, Set

from ldap3.utils.conv import escape_filter_chars

IN_CHAIN = '1.2.840.113556.1.4.1941'   # LDAP_MATCHING_RULE_IN_CHAIN
ADMINISTRATORS_SID = 'S-1-5-32-544'
DOMAIN_ADMINS_RID = 512
ENTERPRISE_ADMINS_RID = 519


class AdminResolver:
    """Cached lookups of privileged groups and their members for one LDAP connection."""

    def __init__(self, ldap_conn):
        self.ldap = ldap_conn
        self.base_dn = ldap_conn.config.base_dn
        self._domain_sid: Optional[str] = None
        self._group_dns: Dict[str, Optional[str]] = {}
        self._admin_dns: Optional[Set[str]] = None

    @property
    def domain_sid(self) -> str:
        if self._domain_sid is None:
            self._domain_sid = self.ldap.get_domain_sid()
        return self._domain_sid

    def admin_group_sids(self) -> List[str]:
        return [ADMINISTRATORS_SID, f'{self.domain_sid}-{DOMAIN_ADMINS_RID}', f'{self.domain_sid}-{ENTERPRISE_ADMINS_RID}']

    def group_dn(self, sid: str) -> Optional[str]:
        """DN of the object with this SID in the domain, or None (e.g. EA in a child domain)."""
        if sid not in self._group_dns:
            result = self.ldap.query(self.base_dn, f'(objectSid={sid})', ['distinguishedName'])
            self._group_dns[sid] = result[0].get('distinguishedName') if result else None
        return self._group_dns[sid]

    def member_filter(self, sids: List[str]) -> str:
        """OR-filter matching direct and nested members of the groups with these SIDs."""
        terms = [f'(memberOf:{IN_CHAIN}:={escape_filter_chars(dn)})'
                 for dn in (self.group_dn(sid) for sid in sids) if dn]
        return f"(|{''.join(terms)})" if terms else ''

    def nested_members(self, group_sid: str, object_filter: str = '', attributes: Optional[List[str]] = None,
                       include_primary_group: bool = False) -> List[Dict]:
        """Direct and nested members of a group, optionally restricted by object_filter.
        Returns [] if the group doesn't exist in this domain."""
        dn = self.group_dn(group_sid)
        if not dn:
            return []
        membership = f'(memberOf:{IN_CHAIN}:={escape_filter_chars(dn)})'
        if include_primary_group and group_sid.startswith(f'{self.domain_sid}-'):
            membership = f"(|{membership}(primaryGroupID={group_sid.rsplit('-', 1)[1]}))"
        return self.ldap.query(self.base_dn, f'(&{object_filter}{membership})',
                               attributes or ['sAMAccountName', 'distinguishedName'])

    def admin_dns(self) -> Set[str]:
        """Lower-cased DNs of the admin groups and all their (nested) members."""
        if self._admin_dns is None:
            dns: Set[str] = set()
            for sid in self.admin_group_sids():
                dn = self.group_dn(sid)
                if not dn:
                    continue
                dns.add(dn.lower())
                for member in self.nested_members(sid, include_primary_group=True):
                    if member.get('distinguishedName'):
                        dns.add(member['distinguishedName'].lower())
            self._admin_dns = dns
        return self._admin_dns

    def is_admin(self, dn: str) -> bool:
        return (dn or '').lower() in self.admin_dns()

    def admin_user_names(self, rid: int) -> Optional[List[str]]:
        """sAMAccountNames of users in the domain group with this RID (nested and
        primary group). None if the group doesn't exist in this domain."""
        sid = f'{self.domain_sid}-{rid}'
        if not self.group_dn(sid):
            return None
        users = self.nested_members(sid, '(objectCategory=person)(objectClass=user)', include_primary_group=True)
        return sorted({u['sAMAccountName'] for u in users if u.get('sAMAccountName')}, key=str.lower)
