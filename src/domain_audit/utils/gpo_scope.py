"""Work out which computers a computer-side GPO setting effectively applies to.

Implements the parts of Group Policy processing that can be read from LDAP
(MS-GPOL):
- links from gPLink on the domain, OUs and sites; link option bit 0x1 =
  disabled, 0x2 = enforced
- block inheritance (gPOptions = 1 on an OU) drops non-enforced links from
  higher levels
- precedence: site < domain < parent OU < child OU for non-enforced links;
  enforced links win over non-enforced ones, and a higher-level enforced link
  wins over a lower-level one
- GPO "flags": 0x2 = computer configuration disabled
- security filtering: the "Apply Group Policy" extended right in the GPO's DACL
  (allow/deny for the computer, its groups incl. nested, its primary group,
  Authenticated Users, Everyone, Enterprise Domain Controllers)

Results that can't be determined from LDAP are reported as 'uncertain':
WMI filters, site-linked GPOs (a computer's site depends on its IP) and two
GPOs linked at the same level with different values (link order within one
gPLink isn't evaluated).
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

import ldap3
from ldap3.utils.conv import escape_filter_chars
from ldap3.utils.dn import to_dn

from .acl import ADS_RIGHT_DS_CONTROL_ACCESS, SD_FLAGS_DACL, right_decisions

APPLY_GROUP_POLICY_GUID = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'
_GPLINK_RE = re.compile(r'\[LDAP://([^;\]]+);(\d+)\]', re.IGNORECASE)
_GUID_RE = re.compile(r'cn=(\{[0-9a-f-]+\})', re.IGNORECASE)

ENFORCED_RANK_BASE = 10000


@dataclass
class GPOInfo:
    guid: str
    name: str
    computer_disabled: bool
    wmi_filter: bool
    allowed_sids: Set[str] = field(default_factory=set)
    denied_sids: Set[str] = field(default_factory=set)
    acl_read: bool = False


@dataclass
class ScopeResult:
    value: Optional[int]          # effective value, None if not configured/undetermined
    status: str                   # 'configured', 'not_configured', 'conflict', 'uncertain'
    reason: str = ''
    gpos: List[str] = field(default_factory=list)


def parse_gplink(gplink: str) -> List[Tuple[str, bool, bool]]:
    """Return [(GPO GUID upper, link_enabled, enforced)] from a gPLink value."""
    links = []
    for dn, options in _GPLINK_RE.findall(gplink or ''):
        match = _GUID_RE.search(dn)
        if not match:
            continue
        options = int(options)
        links.append((match.group(1).upper(), not (options & 0x1), bool(options & 0x2)))
    return links


class GPOScope:
    """Evaluates the effective value of a GPO-delivered computer setting per computer."""

    def __init__(self, ldap_conn, logger=None):
        self.ldap = ldap_conn
        self.logger = logger
        self.base_dn = ldap_conn.config.base_dn
        self.gpos: Dict[str, GPOInfo] = {}
        self.containers: Dict[str, Dict] = {}   # lower DN -> {'links': [...], 'block': bool}
        self.site_links: List[Tuple[str, bool, bool]] = []
        self._loaded = False

    def _debug(self, msg):
        if self.logger:
            self.logger.debug(msg)

    def _paged(self, base, search_filter, attributes, controls=None):
        return [e for e in self.ldap.connection.extend.standard.paged_search(
            search_base=base, search_filter=search_filter, search_scope=ldap3.SUBTREE,
            attributes=attributes, controls=controls, paged_size=500, generator=False
        ) if e.get('type') == 'searchResEntry']

    def load(self):
        if self._loaded:
            return
        domain_sid = self.ldap.get_domain_sid()
        self.domain_sid = domain_sid

        for entry in self._paged(f"CN=Policies,CN=System,{self.base_dn}", '(objectClass=groupPolicyContainer)',
                                 ['cn', 'displayName', 'flags', 'gPCWQLFilter', 'nTSecurityDescriptor'],
                                 controls=SD_FLAGS_DACL):
            attrs, raw = entry['attributes'], entry.get('raw_attributes', {})
            guid = str(attrs.get('cn') or '').upper()
            flags = attrs.get('flags') or 0
            info = GPOInfo(
                guid=guid,
                name=str(attrs.get('displayName') or guid),
                computer_disabled=bool(int(flags) & 0x2),
                wmi_filter=bool(attrs.get('gPCWQLFilter')),
            )
            sd = raw.get('nTSecurityDescriptor') or []
            if sd:
                info.acl_read = True
                for sid, allowed in right_decisions(sd[0], ADS_RIGHT_DS_CONTROL_ACCESS, APPLY_GROUP_POLICY_GUID).items():
                    (info.allowed_sids if allowed else info.denied_sids).add(sid)
            self.gpos[guid] = info

        for entry in self._paged(self.base_dn, '(|(objectClass=domainDNS)(objectClass=organizationalUnit))',
                                 ['distinguishedName', 'gPLink', 'gPOptions']):
            attrs = entry['attributes']
            dn = str(attrs.get('distinguishedName') or entry.get('dn'))
            self.containers[dn.lower()] = {
                'links': parse_gplink(attrs.get('gPLink') or ''),
                'block': int(attrs.get('gPOptions') or 0) & 0x1 == 1,
            }

        try:
            config_dn = self.ldap.get_config_dn()
            for entry in self._paged(f"CN=Sites,{config_dn}", '(objectClass=site)', ['gPLink']):
                self.site_links.extend(parse_gplink(entry['attributes'].get('gPLink') or ''))
        except Exception as e:
            self._debug(f"Could not read site GPO links: {e}")

        self._group_members: Dict[str, Optional[Set[str]]] = {}
        self._loaded = True

    def _members_of_sid(self, sid: str) -> Optional[Set[str]]:
        """Lower-cased DNs of computers that are (nested) members of the group with this SID.
        None if the SID isn't a group in this domain."""
        if sid in self._group_members:
            return self._group_members[sid]
        result = None
        try:
            group = self.ldap.query(self.base_dn, f'(&(objectClass=group)(objectSid={sid}))', ['distinguishedName'])
            if group and group[0].get('distinguishedName'):
                dn = escape_filter_chars(group[0]['distinguishedName'])
                members = self.ldap.query(self.base_dn,
                                          f'(&(objectClass=computer)(memberOf:1.2.840.113556.1.4.1941:={dn}))',
                                          ['distinguishedName'])
                result = {m['distinguishedName'].lower() for m in members if m.get('distinguishedName')}
        except Exception as e:
            self._debug(f"Could not resolve members of {sid}: {e}")
        self._group_members[sid] = result
        return result

    def _computer_sids(self, computer: Dict) -> Set[str]:
        sids = {'S-1-5-11', 'S-1-1-0'}
        if computer.get('objectSid'):
            sids.add(str(computer['objectSid']))
        primary = computer.get('primaryGroupID')
        if primary:
            sids.add(f"{self.domain_sid}-{int(primary)}")
        if int(computer.get('userAccountControl') or 0) & 0x2000:
            sids.add('S-1-5-9')  # Enterprise Domain Controllers
        return sids

    def _gpo_applies(self, gpo: GPOInfo, computer: Dict) -> Tuple[Optional[bool], str]:
        """True/False if the GPO applies to the computer, None if it can't be determined."""
        if gpo.computer_disabled:
            return False, 'computer settings disabled'
        if not gpo.acl_read:
            return None, 'GPO security filtering not readable'
        dn = computer['distinguishedName'].lower()
        own = self._computer_sids(computer)

        def matches(sids: Set[str]) -> bool:
            for sid in sids:
                if sid in own:
                    return True
                members = self._members_of_sid(sid)
                if members and dn in members:
                    return True
            return False

        if matches(gpo.denied_sids):
            return False, 'Apply Group Policy denied (security filtering)'
        if not matches(gpo.allowed_sids):
            return False, 'not in security filtering'
        if gpo.wmi_filter:
            return None, 'WMI filter'
        return True, ''

    def _ancestor_containers(self, dn: str) -> List[str]:
        """Domain root first, then OUs down to the object's parent (lower-cased DNs)."""
        parts = to_dn(dn)
        chain = []
        for i in range(len(parts) - 1, 0, -1):
            candidate = ','.join(parts[i:]).lower()
            if candidate in self.containers:
                chain.append(candidate)
        return chain

    def effective_value(self, computer: Dict, values: Dict[str, int]) -> ScopeResult:
        """Effective value of a setting for one computer.

        values: {GPO GUID (upper, with braces): value set by that GPO}
        """
        self.load()
        candidates = []   # (rank, guid, site_linked)
        for guid, enabled, enforced in self.site_links:
            if enabled:
                candidates.append((ENFORCED_RANK_BASE if enforced else 0, guid, True))
        for level, container in enumerate(self._ancestor_containers(computer['distinguishedName']), start=1):
            info = self.containers[container]
            if info['block']:
                candidates = [c for c in candidates if c[0] >= ENFORCED_RANK_BASE]
            for guid, enabled, enforced in info['links']:
                if enabled:
                    candidates.append((ENFORCED_RANK_BASE - level if enforced else level, guid, False))

        relevant = []  # (rank, guid, applies, reason)
        for rank, guid, site_linked in candidates:
            if guid not in values or guid not in self.gpos:
                continue
            applies, reason = self._gpo_applies(self.gpos[guid], computer)
            if site_linked and applies is not False:
                applies, reason = None, 'site-linked GPO (depends on the computer\'s site)'
            if applies is False:
                continue
            relevant.append((rank, guid, applies, reason))

        if not relevant:
            return ScopeResult(None, 'not_configured')

        top_rank = max(r[0] for r in relevant)
        tier = [r for r in relevant if r[0] == top_rank]
        names = [self.gpos[g].name for _, g, _, _ in tier]
        tier_values = {values[g] for _, g, _, _ in tier}
        uncertain = [r for r in tier if r[2] is None]

        if len(tier_values) > 1:
            if uncertain:
                return ScopeResult(None, 'uncertain', '; '.join(sorted({r[3] for r in uncertain})), names)
            return ScopeResult(None, 'conflict', 'GPOs linked at the same level set different values', names)
        value = tier_values.pop()
        if uncertain and len(uncertain) == len(tier):
            # Only uncertain GPOs decide; lower tiers may still apply instead
            lower = [r for r in relevant if r[0] < top_rank and r[2] is True]
            if not lower or {values[g] for _, g, _, _ in lower} != {value}:
                return ScopeResult(None, 'uncertain', '; '.join(sorted({r[3] for r in uncertain})), names)
        return ScopeResult(value, 'configured', '', names)
