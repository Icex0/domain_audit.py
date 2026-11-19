"""Privileged groups membership checks."""

from pathlib import Path
from typing import Dict, List, Optional, Set

from ldap3.utils.conv import escape_filter_chars

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines

# LDAP_MATCHING_RULE_IN_CHAIN - resolves nested group membership server-side
IN_CHAIN = '1.2.840.113556.1.4.1941'


# Groups that should not contain anyone besides Domain/Enterprise Admins.
# 'sid' is a well-known SID, 'rid' is appended to the domain SID, 'name' is a
# sAMAccountName lookup for groups without a fixed RID.
PRIVILEGED_GROUPS = [
    {'label': 'Account Operators', 'file': 'AccountOperators', 'sid': 'S-1-5-32-548',
     'reason': 'can create/modify most users and groups and log on to DCs'},
    {'label': 'Server Operators', 'file': 'ServerOperators', 'sid': 'S-1-5-32-549',
     'reason': 'can log on to DCs and reconfigure/start services, which runs code as SYSTEM on a DC'},
    {'label': 'Backup Operators', 'file': 'BackupOperators', 'sid': 'S-1-5-32-551',
     'reason': 'can back up the registry and NTDS.dit of DCs and extract all domain hashes'},
    {'label': 'Print Operators', 'file': 'PrintOperators', 'sid': 'S-1-5-32-550',
     'reason': 'can log on to DCs and load printer drivers (SeLoadDriverPrivilege)'},
    {'label': 'Remote Management Users', 'file': 'RemoteManagementUsers', 'sid': 'S-1-5-32-580',
     'reason': 'can connect to DCs over WinRM'},
    {'label': 'Hyper-V Administrators', 'file': 'HyperVAdministrators', 'sid': 'S-1-5-32-578',
     'reason': 'have full control over Hyper-V on DCs, including virtual DCs and their disks'},
    {'label': 'DNS Admins', 'file': 'DNSAdmins', 'name': 'DnsAdmins',
     'reason': 'can make the DNS service on a DC load an arbitrary DLL as SYSTEM'},
    {'label': 'Schema Admins', 'file': 'SchemaAdmins', 'rid': 518,
     'reason': 'can modify the AD schema, including default security descriptors'},
    {'label': 'Key Admins', 'file': 'KeyAdmins', 'rid': 526,
     'reason': 'can write msDS-KeyCredentialLink on domain objects (shadow credentials)'},
    {'label': 'Enterprise Key Admins', 'file': 'EnterpriseKeyAdmins', 'rid': 527,
     'reason': 'can write msDS-KeyCredentialLink on objects forest-wide (shadow credentials)'},
    {'label': 'Group Policy Creator Owners', 'file': 'GroupPolicyCreatorOwners', 'rid': 520,
     'reason': 'can create GPOs; becomes a domain compromise path when combined with link rights'},
]

# Groups that only exist in the forest root domain
FOREST_ROOT_ONLY_RIDS = {518, 519, 527}


class PrivilegedGroupsChecker:
    """Checks for members of high privileged groups that shouldn't have non-admin members."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self._domain_sid: Optional[str] = None
        self._admin_dns: Set[str] = set()

    def _get_domain_sid(self) -> Optional[str]:
        """Get the domain SID."""
        if self._domain_sid:
            return self._domain_sid

        try:
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=domainDNS)',
                attributes=['objectSid']
            )
            if results:
                sid = results[0].get('objectSid', '')
                if isinstance(sid, list):
                    sid = sid[0] if sid else ''
                self._domain_sid = str(sid)
                return self._domain_sid
        except Exception as e:
            self.logger.error(f"[-] Error getting domain SID: {e}")
        return None

    def _find_group(self, group: Dict) -> Optional[Dict]:
        """Look up a group definition from PRIVILEGED_GROUPS (or a SID/RID) in LDAP."""
        if 'sid' in group:
            search_filter = f"(objectSid={group['sid']})"
        elif 'rid' in group:
            domain_sid = self._get_domain_sid()
            if not domain_sid:
                return None
            search_filter = f"(objectSid={domain_sid}-{group['rid']})"
        else:
            search_filter = f"(&(objectClass=group)(sAMAccountName={escape_filter_chars(group['name'])}))"

        results = self.ldap.query(
            search_base=self.base_dn,
            search_filter=search_filter,
            attributes=['distinguishedName', 'sAMAccountName', 'member']
        )
        return results[0] if results else None

    def _get_transitive_members(self, group_dn: str) -> List[Dict]:
        """Return all direct and nested members (users, groups, computers, FSPs) of a group."""
        return self.ldap.query(
            search_base=self.base_dn,
            search_filter=f'(memberOf:{IN_CHAIN}:={escape_filter_chars(group_dn)})',
            attributes=['sAMAccountName', 'cn', 'distinguishedName', 'objectClass']
        )

    def _load_admin_dns(self):
        """Collect DNs of Domain Admins, Enterprise Admins and all their (nested) members."""
        self._admin_dns = set()
        for rid in (512, 519):
            try:
                group = self._find_group({'rid': rid})
                if not group:
                    continue
                group_dn = group.get('distinguishedName', '')
                if not group_dn:
                    continue
                self._admin_dns.add(group_dn.lower())
                for member in self._get_transitive_members(group_dn):
                    dn = member.get('distinguishedName', '')
                    if dn:
                        self._admin_dns.add(dn.lower())
            except Exception as e:
                self.logger.error(f"[-] Error resolving Domain/Enterprise Admins (RID {rid}): {e}")

    @staticmethod
    def _object_type(member: Dict) -> str:
        classes = member.get('objectClass', [])
        if isinstance(classes, str):
            classes = [classes]
        classes = [c.lower() for c in classes]
        if 'computer' in classes:
            return 'computer'
        if 'group' in classes:
            return 'group'
        if 'foreignsecurityprincipal' in classes:
            return 'foreign principal'
        if 'user' in classes:
            return 'user'
        return classes[-1] if classes else 'unknown'

    def check_privileged_groups(self):
        """Run all privileged group membership checks."""
        self.logger.info("---Checking if there are members in high privileged groups---")

        self._load_admin_dns()
        for group in PRIVILEGED_GROUPS:
            self._check_group(group)
        self._check_esx_admins()

    def _check_esx_admins(self):
        """Information for CVE-2024-37085: domain-joined ESXi (before 8.0 U3) gives
        full admin to members of a domain group named "ESX Admins", without
        checking it is the intended group. Whether ESXi hosts are domain-joined
        can't be seen reliably from LDAP, so this is information only."""
        try:
            result = self.ldap.query(self.base_dn, '(&(objectClass=group)(sAMAccountName=ESX Admins))',
                                     ['distinguishedName'])
            if result and result[0].get('distinguishedName'):
                members = self._get_transitive_members(result[0]['distinguishedName'])
                names = sorted(m.get('sAMAccountName') or m.get('cn') or '' for m in members)
                self.logger.info(f"[*] 'ESX Admins' group exists with {len(names)} member(s)"
                                 f"{': ' + ', '.join(names) if names else ''} - members are root on domain-joined "
                                 "ESXi hosts; check who can modify this group (CVE-2024-37085)")
            else:
                self.logger.info("[*] No 'ESX Admins' group - if ESXi hosts are domain-joined (before 8.0 U3), anyone "
                                 "who can create or rename a group to this name gets root on them (CVE-2024-37085)")
        except Exception as e:
            self.logger.debug(f"Could not check ESX Admins group: {e}")

    def _check_group(self, group: Dict):
        """Report members of a privileged group that aren't Domain/Enterprise Admins."""
        label = group['label']
        try:
            group_obj = self._find_group(group)
            if not group_obj:
                if group.get('rid') in FOREST_ROOT_ONLY_RIDS:
                    self.logger.info(f"[*] {label} group not found (it only exists in the forest root domain)")
                else:
                    self.logger.info(f"[*] {label} group not found")
                return

            group_dn = group_obj.get('distinguishedName', '')
            direct = group_obj.get('member') or []
            if isinstance(direct, str):
                direct = [direct]
            direct_dns = {dn.lower() for dn in direct}

            members = []
            for member in self._get_transitive_members(group_dn):
                dn = member.get('distinguishedName', '')
                if not dn or dn.lower() in self._admin_dns:
                    continue
                members.append(member)
        except Exception as e:
            self.logger.error(f"[-] Error checking {label} membership: {e}")
            return

        if not members:
            self.logger.success(f"[+] There are no members in the {label} group that aren't Domain- or Enterprise Administrators")
            return

        self.logger.finding(
            f"{len(members)} members in the {label} group that aren't Domain- or Enterprise Administrators"
        )
        lines = [
            f"Group: {label} ({group_dn})",
            f"Risk: members {group['reason']}",
            "",
            "Members (excluding Domain/Enterprise Admins and their nested members):",
        ]
        for member in sorted(members, key=lambda m: (m.get('sAMAccountName') or m.get('cn') or '').lower()):
            name = member.get('sAMAccountName') or member.get('cn') or member.get('distinguishedName')
            membership = 'direct' if member['distinguishedName'].lower() in direct_dns else 'nested'
            lines.append(f"  {name} ({self._object_type(member)}, {membership}) - {member['distinguishedName']}")

        write_lines(lines, self.output_paths['findings'] / f"users_highprivilegegroups_{group['file']}.txt")
