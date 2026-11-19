"""Check which non-admin principals can log on to domain controllers over RDP.

The RDP logon right on a DC is "Allow log on through Remote Desktop Services"
(SeRemoteInteractiveLogonRight) minus "Deny log on through Remote Desktop
Services" (SeDenyRemoteInteractiveLogonRight). Microsoft's effective default on
DCs is Administrators only; Remote Desktop Users only get it on member servers
and workstations.

Sources, in order of reliability:
1. LSA (MS-LSAD LsarEnumerateAccountsWithUserRight) on each DC: the effective
   rights including local policy. Requires admin rights on the DC.
2. Otherwise the GPO-defined value ([Privilege Rights] in GptTmpl.inf),
   evaluated per DC with utils.gpo_scope; if no GPO defines it, the documented
   default (Administrators). Local policy can add principals that this can't
   see, so that case is reported as "verify".
"""

import io
import socket
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from ldap3.utils.conv import escape_filter_chars

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.gpttmpl import parse_gpttmpl_inf

ALLOW_RIGHT = 'SeRemoteInteractiveLogonRight'
DENY_RIGHT = 'SeDenyRemoteInteractiveLogonRight'
DEFAULT_DC_RDP_SIDS = {'S-1-5-32-544'}  # Administrators
RDP_USERS_SID = 'S-1-5-32-555'          # Remote Desktop Users
# Well-known SIDs that are (or contain) admins / the system - not "normal users"
ADMIN_WELL_KNOWN = {'S-1-5-32-544', 'S-1-5-18', 'S-1-5-9'}
CHAIN = '1.2.840.113556.1.4.1941'


class DCRDPChecker:
    """Reports non-admin principals that are allowed to RDP to domain controllers."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password or ''
        self.lmhash, self.nthash = '', ''
        if hashes:
            self.lmhash, self.nthash = hashes.split(':') if ':' in hashes else ('', hashes)
        self._sid_cache: Dict[str, Optional[Dict]] = {}

    # ---------- principal resolution ----------

    def _domain_sid(self) -> str:
        if not hasattr(self, '_dsid'):
            self._dsid = self.ldap.get_domain_sid()
        return self._dsid

    def _admin_user_dns(self) -> Set[str]:
        """Lower-cased DNs of all (nested) members of Administrators, Domain Admins, Enterprise Admins."""
        if hasattr(self, '_admins'):
            return self._admins
        admins: Set[str] = set()
        for sid in ('S-1-5-32-544', f'{self._domain_sid()}-512', f'{self._domain_sid()}-519'):
            group = self.ldap.query(self.base_dn, f'(objectSid={sid})', ['distinguishedName'])
            if not group or not group[0].get('distinguishedName'):
                continue
            dn = group[0]['distinguishedName']
            admins.add(dn.lower())
            for m in self.ldap.query(self.base_dn, f'(memberOf:{CHAIN}:={escape_filter_chars(dn)})', ['distinguishedName']):
                if m.get('distinguishedName'):
                    admins.add(m['distinguishedName'].lower())
        rid_filter = f'(|(primaryGroupID=512)(primaryGroupID=519))'
        for m in self.ldap.query(self.base_dn, f'(&(objectClass=user){rid_filter})', ['distinguishedName']):
            if m.get('distinguishedName'):
                admins.add(m['distinguishedName'].lower())
        self._admins = admins
        return admins

    def _lookup_sid(self, sid: str) -> Optional[Dict]:
        if sid not in self._sid_cache:
            result = self.ldap.query(self.base_dn, f'(objectSid={sid})',
                                     ['sAMAccountName', 'distinguishedName', 'objectClass'])
            self._sid_cache[sid] = result[0] if result else None
        return self._sid_cache[sid]

    def _resolve_token(self, token: str) -> Optional[str]:
        """GptTmpl.inf lists principals as '*SID' or as (DOMAIN\\)name. Return a SID."""
        token = token.strip().strip('"')
        if not token:
            return None
        if token.startswith('*'):
            return token[1:]
        if token.upper().startswith('S-1-'):
            return token
        name = token.split('\\')[-1]
        result = self.ldap.query(self.base_dn, f'(sAMAccountName={escape_filter_chars(name)})', ['objectSid'])
        if result and result[0].get('objectSid'):
            return str(result[0]['objectSid'])
        self.logger.debug(f"Could not resolve principal '{token}' to a SID")
        return None

    def _non_admin_principals(self, sids: Set[str]) -> List[str]:
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

    # ---------- rights sources ----------

    def _lsa_rights(self, host: str) -> Optional[Tuple[Set[str], Set[str]]]:
        """Effective (allow, deny) SIDs from the DC's LSA, or None if not permitted."""
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
            rights = []
            for right in (ALLOW_RIGHT, DENY_RIGHT):
                try:
                    resp = lsad.hLsarEnumerateAccountsWithUserRight(dce, handle, right)
                    rights.append({e['Sid'].formatCanonical() for e in resp['EnumerationBuffer']['Information']})
                except lsad.DCERPCSessionError as e:
                    if 'STATUS_NO_MORE_ENTRIES' in str(e) or 'STATUS_NO_SUCH_PRIVILEGE' in str(e):
                        rights.append(set())  # nobody has this right
                    else:
                        raise
            dce.disconnect()
            return rights[0], rights[1]
        except Exception as e:
            self.logger.debug(f"LSA user rights enumeration on {host} not possible: {e}")
            return None

    def _gpo_privilege_rights(self) -> Dict[str, Dict[str, str]]:
        """{GPO GUID upper: {'allow': raw value, 'deny': raw value}} from SYSVOL GptTmpl.inf files."""
        from impacket.smbconnection import SMBConnection
        server = self.ldap.config.server
        conn = SMBConnection(server, server)
        conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
        values: Dict[str, Dict[str, str]] = {}
        try:
            for entry in conn.listPath('SYSVOL', f"{self.domain}/Policies/*"):
                guid = entry.get_longname()
                if guid in ('.', '..') or not entry.is_directory():
                    continue
                buf = io.BytesIO()
                try:
                    conn.getFile('SYSVOL', f"{self.domain}/Policies/{guid}/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf", buf.write)
                except Exception:
                    continue
                rights = parse_gpttmpl_inf(buf.getvalue()).get('Privilege Rights', {})
                found = {}
                if ALLOW_RIGHT.lower() in rights:
                    found['allow'] = rights[ALLOW_RIGHT.lower()] or ''
                if DENY_RIGHT.lower() in rights:
                    found['deny'] = rights[DENY_RIGHT.lower()] or ''
                if found:
                    values[guid.upper()] = found
        finally:
            conn.logoff()
        return values

    def _sids_from_value(self, value: str) -> Set[str]:
        return {sid for sid in (self._resolve_token(t) for t in value.split(',')) if sid}

    # ---------- check ----------

    def check_dc_rdp(self):
        self.logger.info("---Checking which non-admins can log on to domain controllers over RDP---")
        try:
            dcs = self.ldap.query(
                self.base_dn,
                '(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))',
                ['sAMAccountName', 'dNSHostName', 'distinguishedName', 'objectSid', 'primaryGroupID', 'userAccountControl']
            )
        except Exception as e:
            self.logger.error(f"[-] Could not list domain controllers: {e}")
            return
        if not dcs:
            self.logger.info("[*] No domain controllers found")
            return

        gpo_values = None
        scope = None
        findings: List[str] = []
        verify: List[str] = []

        for dc in dcs:
            name = dc.get('sAMAccountName', '').rstrip('$') or dc['distinguishedName']
            host = dc.get('dNSHostName') or self.ldap.config.server
            rdp_open = self._port_open(host, 3389)
            port_note = '' if rdp_open else ' (port 3389 not reachable from here)'

            lsa = self._lsa_rights(host) if self.username else None
            if lsa is not None:
                allow, deny = lsa
                source = 'effective rights from the DC (LSA)'
                local_policy_unknown = False
            else:
                try:
                    if gpo_values is None:
                        gpo_values = self._gpo_privilege_rights()
                        from ...utils.gpo_scope import GPOScope
                        scope = GPOScope(self.ldap, self.logger)
                    allow_vals = {g: v['allow'] for g, v in gpo_values.items() if 'allow' in v}
                    deny_vals = {g: v['deny'] for g, v in gpo_values.items() if 'deny' in v}
                    allow_res = scope.effective_value(dc, allow_vals)
                    deny_res = scope.effective_value(dc, deny_vals)
                except Exception as e:
                    self.logger.warning(f"[!] {name}: could not read RDP logon rights ({e}) - verify manually")
                    verify.append(f"{name}: RDP logon right could not be determined ({e})")
                    continue
                if 'conflict' in (allow_res.status, deny_res.status) or 'uncertain' in (allow_res.status, deny_res.status):
                    verify.append(f"{name}: GPO for RDP logon right {allow_res.status}/{deny_res.status} - "
                                  f"{allow_res.reason or deny_res.reason}")
                    continue
                allow = self._sids_from_value(allow_res.value) if allow_res.status == 'configured' else set(DEFAULT_DC_RDP_SIDS)
                deny = self._sids_from_value(deny_res.value) if deny_res.status == 'configured' else set()
                source = ('GPO' if allow_res.status == 'configured' else 'Windows default for DCs (no GPO defines it)')
                local_policy_unknown = True

            principals = self._non_admin_principals(allow - deny)
            if principals:
                findings.append(f"{name}{port_note} - source: {source}")
                findings.extend(f"  {p}" for p in principals)
            elif local_policy_unknown:
                rdu = self._non_admin_principals({RDP_USERS_SID})
                note = f"; Remote Desktop Users has non-admin members ({rdu[0].split(' - ', 1)[-1]})" if rdu else ''
                verify.append(f"{name}: no non-admin RDP logon right via {source}, but local policy can't be read "
                              f"with these credentials (run as admin for effective rights){note}")

        if findings:
            self.logger.finding("Non-admin principals can log on to domain controllers over RDP")
            write_lines(findings, self.output_paths['findings'] / 'dc_rdp_access.txt')
        else:
            self.logger.success("[+] No non-admin principals with the RDP logon right on domain controllers found")
        if verify:
            self.logger.warning(f"[!] RDP logon rights on {len(verify)} DC(s) need manual verification")
            write_lines(verify, self.output_paths['checks'] / 'dc_rdp_access_verify.txt')

    @staticmethod
    def _port_open(host: str, port: int) -> bool:
        try:
            with socket.create_connection((host, port), timeout=3):
                return True
        except OSError:
            return False
