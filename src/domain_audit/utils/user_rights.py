"""Effective user rights (privileges) on domain controllers.

Sources, in order of reliability:
1. LSA (MS-LSAD LsarEnumerateAccountsWithUserRight) on the DC: the effective
   assignment, including local policy. Requires admin rights on the DC.
2. The GPO-defined value ([Privilege Rights] in GptTmpl.inf), evaluated per DC
   with utils.gpo_scope. A GPO-defined user right replaces the local value.
3. The documented Windows default for DCs, when no GPO defines the right
   (local policy could still differ - reported as not certain).
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from ldap3.utils.conv import escape_filter_chars

from .admins import AdminResolver
from .sysvol import SysvolClient
from .dc import get_domain_controllers

# Well-known SIDs that are (or contain) admins / the system - not "normal users"
ADMIN_WELL_KNOWN = {'S-1-5-32-544', 'S-1-5-18', 'S-1-5-9'}
CHAIN = '1.2.840.113556.1.4.1941'


@dataclass
class RightResult:
    sids: Set[str] = field(default_factory=set)
    source: str = ''
    certain: bool = True          # False when local policy could add principals
    error: str = ''               # set when the value couldn't be determined


class DCUserRights:
    """Resolves which SIDs hold a user right on each DC (allow minus deny)."""

    def __init__(self, ldap_conn, logger, domain: str, username: str = None,
                 password: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.logger = logger
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password or ''
        self.lmhash, self.nthash = '', ''
        if hashes:
            self.lmhash, self.nthash = hashes.split(':') if ':' in hashes else ('', hashes)
        self._gpo_rights: Optional[Dict[str, Dict[str, str]]] = None
        self._sid_cache: Dict[str, Optional[Dict]] = {}
        self.admins = AdminResolver(ldap_conn)
        self._scope = None

    # ---- LSA ----
    def lsa_holders(self, host: str, right: str) -> Optional[Set[str]]:
        """SIDs holding `right` according to the DC's LSA, or None if not permitted."""
        if not self.username:
            return None
        from impacket.dcerpc.v5 import transport, lsad
        from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED
        try:
            rpc = transport.DCERPCTransportFactory(rf'ncacn_np:{host}[\pipe\lsarpc]')
            rpc.set_credentials(self.username, self.password, self.domain, self.lmhash, self.nthash)
            rpc.set_connect_timeout(10)
            dce = rpc.get_dce_rpc()
            dce.connect()
            dce.bind(lsad.MSRPC_UUID_LSAD)
            handle = lsad.hLsarOpenPolicy2(dce, MAXIMUM_ALLOWED)['PolicyHandle']
            try:
                resp = lsad.hLsarEnumerateAccountsWithUserRight(dce, handle, right)
                sids = {e['Sid'].formatCanonical() for e in resp['EnumerationBuffer']['Information']}
            except lsad.DCERPCSessionError as e:
                if 'STATUS_NO_MORE_ENTRIES' in str(e) or 'STATUS_NO_SUCH_PRIVILEGE' in str(e):
                    sids = set()   # nobody holds this right
                else:
                    raise
            dce.disconnect()
            return sids
        except Exception as e:
            self.logger.debug(f"LSA enumeration of {right} on {host} not possible: {e}")
            return None

    # ---- GPO ----
    def _load_gpo_rights(self) -> Dict[str, Dict[str, str]]:
        """{GPO GUID upper: {right lowercase: raw value}} from the GPOs' GptTmpl.inf."""
        if self._gpo_rights is None:
            sysvol = SysvolClient.shared(self.ldap, self.domain, self.username, self.password,
                                         f"{self.lmhash}:{self.nthash}" if self.nthash else None, self.logger)
            values: Dict[str, Dict[str, str]] = {}
            for guid in sysvol.gpo_folders():
                rights = sysvol.gpttmpl(guid).get('Privilege Rights', {})
                if rights:
                    values[guid.upper()] = {k: (v or '') for k, v in rights.items()}
            self._gpo_rights = values
        return self._gpo_rights

    def gpo_value(self, dc: Dict, right: str):
        """Effective GPO value (ScopeResult) of `right` for this DC."""
        from .gpo_scope import GPOScope
        if self._scope is None:
            self._scope = GPOScope(self.ldap, self.logger)
        values = {g: r[right.lower()] for g, r in self._load_gpo_rights().items() if right.lower() in r}
        return self._scope.effective_value(dc, values)

    # ---- name resolution ----
    def resolve(self, value: str) -> Set[str]:
        """GptTmpl.inf lists principals as '*SID' or (DOMAIN\\)name; return SIDs."""
        sids = set()
        for token in (value or '').split(','):
            token = token.strip().strip('"')
            if not token:
                continue
            if token.startswith('*'):
                sids.add(token[1:])
            elif token.upper().startswith('S-1-'):
                sids.add(token)
            else:
                name = token.split('\\')[-1]
                result = self.ldap.query(self.base_dn, f'(sAMAccountName={escape_filter_chars(name)})', ['objectSid'])
                if result and result[0].get('objectSid'):
                    sids.add(str(result[0]['objectSid']))
                else:
                    self.logger.debug(f"Could not resolve principal '{token}' to a SID")
        return sids

    # ---- principal classification ----
    def _domain_sid(self) -> str:
        return self.admins.domain_sid

    def _admin_user_dns(self) -> Set[str]:
        """Lower-cased DNs of all admins (see utils.admins)."""
        return self.admins.admin_dns()

    def _lookup_sid(self, sid: str) -> Optional[Dict]:
        if sid not in self._sid_cache:
            result = self.ldap.query(self.base_dn, f'(objectSid={sid})',
                                     ['sAMAccountName', 'distinguishedName', 'objectClass'])
            self._sid_cache[sid] = result[0] if result else None
        return self._sid_cache[sid]

    def non_admin_principals(self, sids: Set[str]) -> List[str]:
        """Describe principals in `sids` that give RDP to non-admin users."""
        domain_sid = self._domain_sid()
        broad = {
            'S-1-1-0': 'Everyone', 'S-1-5-11': 'Authenticated Users', 'S-1-5-7': 'Anonymous Logon',
            'S-1-5-32-545': 'Users', f'{domain_sid}-513': 'Domain Users', f'{domain_sid}-515': 'Domain Computers',
        }
        admins = self._admin_user_dns()
        results = []
        for sid in sorted(sids):
            if sid in ADMIN_WELL_KNOWN or sid in (f'{domain_sid}-512', f'{domain_sid}-519'):
                continue
            if sid in broad:
                results.append(f"{broad[sid]} ({sid}) - every user in that group")
                continue
            obj = self._lookup_sid(sid)
            if not obj:
                results.append(f"{sid} (not resolvable in this domain - foreign or deleted principal)")
                continue
            dn = obj['distinguishedName']
            classes = [c.lower() for c in (obj.get('objectClass') or [])]
            name = obj.get('sAMAccountName') or dn
            if 'group' in classes:
                users = self.ldap.query(
                    self.base_dn,
                    f'(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                    f'(memberOf:{CHAIN}:={escape_filter_chars(dn)}))',
                    ['sAMAccountName', 'distinguishedName'])
                non_admin = sorted(u['sAMAccountName'] for u in users
                                   if u.get('distinguishedName', '').lower() not in admins and u.get('sAMAccountName'))
                if non_admin:
                    results.append(f"{name} (group, {sid}) - non-admin members: {', '.join(non_admin)}")
            elif dn.lower() not in admins:
                results.append(f"{name} ({'computer' if 'computer' in classes else 'user'}, {sid})")
        return results

    # ---- combined ----
    def holders(self, dc: Dict, allow_right: str, deny_right: Optional[str], default_sids: Set[str]) -> RightResult:
        """Effective holders of allow_right minus deny_right on one DC."""
        host = dc.get('dNSHostName') or self.ldap.config.server
        allow = self.lsa_holders(host, allow_right)
        if allow is not None:
            deny = self.lsa_holders(host, deny_right) if deny_right else set()
            return RightResult(allow - (deny or set()), 'effective rights from the DC (LSA)', True)
        try:
            allow_res = self.gpo_value(dc, allow_right)
            deny_res = self.gpo_value(dc, deny_right) if deny_right else None
        except Exception as e:
            return RightResult(error=f"could not read user rights ({e})")
        for res in (allow_res, deny_res):
            if res is not None and res.status in ('conflict', 'uncertain'):
                return RightResult(error=f"GPO {res.status}: {res.reason}")
        if allow_res.status == 'configured':
            allow_sids, source, certain = self.resolve(allow_res.value), f"GPO ({', '.join(allow_res.gpos)})", True
        else:
            allow_sids, source, certain = set(default_sids), 'Windows default for DCs (no GPO defines it)', False
        deny_sids = self.resolve(deny_res.value) if deny_res is not None and deny_res.status == 'configured' else set()
        return RightResult(allow_sids - deny_sids, source, certain)


@dataclass
class ComputerCreation:
    """Whether normal users can create computer accounts (MachineAccountQuota path)."""
    possible: Optional[bool]        # True / False / None (couldn't be determined)
    quota: int
    principals: List[str] = field(default_factory=list)
    sources: Set[str] = field(default_factory=set)
    errors: List[str] = field(default_factory=list)


def users_can_create_computers(ldap_conn, logger, domain: str, username: str = None,
                               password: str = None, hashes: str = None) -> ComputerCreation:
    """A normal user can create computer accounts when ms-DS-MachineAccountQuota > 0
    AND non-admins hold "Add workstations to domain" (SeMachineAccountPrivilege)
    on the DCs - by default Authenticated Users via the Default Domain
    Controllers Policy. Delegated create-computer rights on OUs aren't covered.
    """
    base_dn = ldap_conn.config.base_dn
    result = ldap_conn.query(base_dn, '(objectClass=domain)', ['ms-DS-MachineAccountQuota'])
    raw = result[0].get('ms-DS-MachineAccountQuota') if result else None
    quota = int(raw) if str(raw).lstrip('-').isdigit() else 10  # default 10
    if quota <= 0:
        return ComputerCreation(False, quota)

    rights = DCUserRights(ldap_conn, logger, domain, username, password, hashes)
    dcs = get_domain_controllers(ldap_conn)
    holders, sources, errors = set(), set(), []
    for dc in dcs:
        res = rights.holders(dc, 'SeMachineAccountPrivilege', None, {'S-1-5-11'})  # default: Authenticated Users
        if res.error:
            errors.append(f"{dc.get('sAMAccountName', '')}: {res.error}")
            continue
        holders |= res.sids
        sources.add(res.source)
    principals = rights.non_admin_principals(holders)
    if principals:
        return ComputerCreation(True, quota, principals, sources, errors)
    if errors:
        return ComputerCreation(None, quota, [], sources, errors)
    return ComputerCreation(False, quota, [], sources, errors)
