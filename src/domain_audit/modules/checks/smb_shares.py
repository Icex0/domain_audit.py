"""Share enumeration as the audit user, and credentials on deployment shares.

Lists the shares the current user can read or write on every SMB host found by
the network scan (NetExec --shares; its default write check reads the share ACL
and creates nothing). Deployment shares are then checked for credentials:

- MDT (DeploymentShare$): Control/Bootstrap.ini and CustomSettings.ini hold the
  account the boot media uses to connect (UserID/UserPassword) and often the
  domain join account (DomainAdmin/DomainAdminPassword) and the local
  Administrator password for deployed machines (AdminPassword). Task sequence
  Unattend.xml files can hold the same, base64-encoded when PlainText=false.
- REMINST (WDS/SCCM PXE): boot images and PXE media variable files; these need
  manual analysis (e.g. .wim mounting), so they are reported for review.
"""

import base64
import configparser
import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.sysvol import SysvolClient, has_credentials
from ...utils.targets import TargetFiles, TargetScope

# Shares every authenticated user can read by design
DEFAULT_SHARES = {'ipc$', 'print$'}
DC_SHARES = {'sysvol', 'netlogon'}
MDT_FILES = ('Control/Bootstrap.ini', 'Control/CustomSettings.ini')
MAX_TASK_SEQUENCES = 100

_ROW = re.compile(r'^SMB\s+(\S+)\s+\d+\s+(\S+)\s+(.*)$')
_PERM = r'(?:READ|WRITE)(?: \((?:SUBDIR|ACL)\))?'
_PERMS_AT_START = re.compile(rf'^({_PERM}(?:,{_PERM})*)(?:\s+(.*))?$')
_PERMS = re.compile(rf'\s+({_PERM}(?:,{_PERM})*)(?:\s+(.*))?$')

# MDT rule keys that hold a password, with the key holding the matching user
_MDT_PASSWORD_KEYS = {
    'userpassword': ('userid', 'userdomain'),
    'domainadminpassword': ('domainadmin', 'domainadmindomain'),
    'adminpassword': (None, None),  # local Administrator password of deployed machines
}


def _clean(value: str) -> str:
    return value.strip().strip('"').strip()


def _is_placeholder(value: str) -> bool:
    value = value.strip()
    return (not value or value.startswith('%') and value.endswith('%')
            or value == '*SENSITIVE*DATA*DELETED*')


def parse_shares_output(output: str) -> List[Dict[str, str]]:
    """Parse 'netexec smb --shares' output into accessible shares.

    Rows follow the 'Share  Permissions  Remark' header that NetExec prints per
    host; shares without READ/WRITE are skipped.
    """
    shares = []
    in_table: Dict[str, bool] = {}
    perms_column: Dict[str, int] = {}
    for line in re.sub(r'\x1b\[[0-9;]*m', '', output).split('\n'):
        match = _ROW.match(line.strip())
        if not match:
            continue
        ip, hostname, msg = match.groups()
        if msg.startswith('Share') and 'Permissions' in msg:
            in_table[ip] = True
            perms_column[ip] = msg.index('Permissions')
            continue
        if msg.startswith('[') or set(msg) <= set('- '):
            if msg.startswith('['):
                in_table[ip] = False
            continue
        if not in_table.get(ip):
            continue
        column = perms_column.get(ip, 0)
        if column and len(msg) > column and msg[column - 1] == ' ' and msg[:column].strip():
            # Share name fits its column: permissions start exactly at the header's
            # 'Permissions' column, so a word like READ in the remark is not taken.
            perms = _PERMS_AT_START.match(msg[column:])
            if not perms:
                continue
            name = msg[:column].strip()
        else:
            # Name longer than its column pushes the rest to the right
            perms = _PERMS.search(msg)
            if not perms:
                continue
            name = msg[:perms.start()].strip()
        if name:
            shares.append({'ip': ip, 'hostname': hostname, 'share': name,
                           'access': perms.group(1), 'remark': (perms.group(2) or '').strip()})
    return shares


def parse_mdt_ini(content: bytes) -> List[str]:
    """Credentials from an MDT Bootstrap.ini / CustomSettings.ini."""
    text = content.decode('utf-16') if content.startswith((b'\xff\xfe', b'\xfe\xff')) \
        else content.decode('utf-8-sig', errors='ignore')
    parser = configparser.ConfigParser(interpolation=None, strict=False, allow_no_value=True,
                                       delimiters=('=',), comment_prefixes=(';', '#'))
    parser.optionxform = str.lower
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    results = []
    for section in parser.sections():
        values = {k: _clean(v or '') for k, v in parser.items(section)}
        for key, (user_key, domain_key) in _MDT_PASSWORD_KEYS.items():
            password = values.get(key, '')
            if _is_placeholder(password):
                continue
            if user_key:
                user = values.get(user_key, '') or '?'
                domain = values.get(domain_key, '')
                account = f"{domain}\\{user}" if domain else user
                results.append(f"[{section}] {key}: {account} / {password}")
            else:
                results.append(f"[{section}] {key} (local Administrator of deployed machines): {password}")
    return results


def _decode_unattend_password(value: str, plain_text: bool, suffix: str) -> str:
    if plain_text:
        return value
    try:
        decoded = base64.b64decode(value).decode('utf-16-le')
    except Exception:
        return value
    # Windows SIM appends the element name before encoding
    for tail in (suffix, 'Password'):
        if decoded.endswith(tail):
            return decoded[:-len(tail)]
    return decoded


def parse_unattend(content: bytes) -> List[str]:
    """Passwords from an Unattend.xml (AdministratorPassword, AutoLogon, domain join)."""
    text = content.decode('utf-16') if content.startswith((b'\xff\xfe', b'\xfe\xff')) \
        else content.decode('utf-8-sig', errors='ignore')
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    local = lambda el: el.tag.split('}')[-1]
    parents = {child: parent for parent in root.iter() for child in parent}
    results = []
    for el in root.iter():
        name = local(el)
        if name not in ('AdministratorPassword', 'Password'):
            continue
        children = {local(c): (c.text or '') for c in el}
        if 'Value' in children:
            value = children['Value'].strip()
            plain = children.get('PlainText', 'true').strip().lower() != 'false'
        else:
            value, plain = (el.text or '').strip(), True
        if _is_placeholder(value):
            continue
        password = _decode_unattend_password(value, plain, name)
        if not password:
            continue
        parent = parents.get(el)
        context = local(parent) if parent is not None else ''
        user = ''
        if parent is not None:
            siblings = {local(c): (c.text or '').strip() for c in parent}
            user = siblings.get('Username') or siblings.get('Name') or ''
            if siblings.get('Domain'):
                user = f"{siblings['Domain']}\\{user}"
        label = f"{context}/{name}" if context else name
        results.append(f"{label}: {user + ' / ' if user else ''}{password}")
    return results


class SMBShareChecker:
    """Readable/writable shares for the audit user and deployment share credentials."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None,
                 username: str = None, password: str = None, hashes: str = None,
                 target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_files = target_files or TargetFiles(output_paths['data'], TargetScope(), self.logger)

    def check_shares(self):
        self.logger.info("---Enumerating shares accessible to the current user---")
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning("[!] Share enumeration requires credentials")
            return
        hosts = self.target_files.read_discovered('scandata_hostalive_smb.txt', "SMB").targets
        if not hosts:
            return

        output = self._run_netexec_shares(hosts)
        if not output:
            return
        write_lines(output.split('\n'), self.output_paths['data'] / 'netexec_shares.txt')
        shares = parse_shares_output(output)
        accessible = [s for s in shares if s['share'].lower() not in DEFAULT_SHARES]
        if not accessible:
            self.logger.info("[*] No accessible shares found (besides IPC$/print$)")
            return

        self.logger.info(f"[*] {len(accessible)} share(s) readable or writable by the current user "
                         f"on {len({s['ip'] for s in accessible})} host(s) (saved to data)")
        write_lines([f"\\\\{s['ip']}\\{s['share']}  {s['access']}  ({s['hostname']})"
                     + (f"  {s['remark']}" if s['remark'] else '') for s in accessible],
                    self.output_paths['data'] / 'readable_shares.txt')

        writable = [s for s in accessible if 'WRITE' in s['access']
                    and s['share'].lower() not in DC_SHARES]
        dc_writable = [s for s in accessible if 'WRITE' in s['access'] and s['share'].lower() in DC_SHARES]
        if writable:
            self.logger.warning(f"[!] {len(writable)} share(s) writable by the current user - review for "
                                "scripts/executables others run")
            write_lines(["Shares the current user can write to (NetExec ACL-based check). Review whether",
                         "they contain scripts, executables or shortcuts that other users or systems run,",
                         "and whether domain-wide write access is intended:", ""] +
                        [f"\\\\{s['ip']}\\{s['share']}  {s['access']}  ({s['hostname']})" for s in writable],
                        self.output_paths['checks'] / 'writable_shares.txt')
        if dc_writable:
            self.logger.finding(f"SYSVOL/NETLOGON writable by the current user on {len(dc_writable)} share(s)")
            write_lines([f"\\\\{s['ip']}\\{s['share']}  {s['access']}  ({s['hostname']})" for s in dc_writable] +
                        ["", "Write access to SYSVOL/NETLOGON allows changing logon scripts or GPO files that",
                         "domain computers and users run."],
                        self.output_paths['findings'] / 'sysvol_netlogon_writable.txt')

        self._check_deployment_shares(accessible)

    def _run_netexec_shares(self, hosts: List[str]) -> str:
        with self.target_files.temporary_targets(hosts) as hosts_file:
            cmd = ['netexec', 'smb', str(hosts_file), '-d', self.domain, '-u', self.username]
            cmd += ['-H', self.hashes] if self.hashes and not self.password else ['-p', self.password]
            cmd.append('--shares')
            self.logger.info(f"[*] Running netexec --shares against {len(hosts)} SMB host(s)")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8',
                                        errors='replace', timeout=1800)
            except subprocess.TimeoutExpired:
                self.logger.error("[-] netexec --shares timed out")
                return ""
            except FileNotFoundError:
                self.logger.error("[-] netexec not found on system")
                return ""
        return (result.stdout or '') + (result.stderr or '')

    @staticmethod
    def _deployment_kind(share: str) -> Optional[str]:
        name = share.lower()
        if name == 'reminst':
            return 'reminst'
        if 'deploy' in name or 'mdt' in name:
            return 'mdt'
        return None

    def _client(self, host: str) -> SysvolClient:
        return SysvolClient(self.ldap, self.domain, self.username, self.password, self.hashes,
                            self.logger, host=host)

    def _check_deployment_shares(self, shares: List[Dict[str, str]]):
        deployment = [(s, self._deployment_kind(s['share'])) for s in shares
                      if self._deployment_kind(s['share']) and 'READ' in s['access']]
        if not deployment:
            return
        self.logger.info("---Checking deployment shares (MDT/WDS) for credentials---")
        credentials, review = [], []
        for share, kind in deployment:
            unc = f"\\\\{share['ip']}\\{share['share']}"
            client = self._client(share['ip'])
            try:
                if kind == 'mdt':
                    found = self._mdt_credentials(client, share['share'])
                    if found:
                        credentials.append(f"{unc} ({share['hostname']})")
                        credentials.extend(f"  {line}" for line in found)
                        credentials.append("")
                    review.append(f"{unc}: MDT share - check boot images (Boot\\*.wim, e.g. LiteTouchPE_x64.wim) "
                                  "for Bootstrap.ini/Unattend.xml credentials")
                else:
                    review.append(f"{unc}: WDS/PXE share - check boot images (Boot\\x64\\Images\\*.wim) and SCCM "
                                  "PXE media variable files (SMSTemp\\*.var) for credentials")
            finally:
                client.close()

        if credentials:
            self.logger.finding("Credentials found on deployment share(s) readable by the current user")
            write_lines(["Credentials in MDT deployment share files readable by the current user:", ""] +
                        credentials +
                        ["UserID/UserPassword: account the boot media uses to connect to the share.",
                         "DomainAdmin/DomainAdminPassword: domain join account.",
                         "AdminPassword: local Administrator password set on deployed machines.",
                         "",
                         "Recommendation: remove the credentials from the rules/unattend files (prompt or",
                         "use a dedicated least-privilege account), restrict share access to the deployment",
                         "account and rotate the exposed passwords."],
                        self.output_paths['findings'] / 'deployment_share_credentials.txt')
        else:
            self.logger.info("[*] No credentials found in MDT rule/unattend files on deployment shares")
        if review:
            self.logger.warning(f"[!] {len(review)} deployment share(s) readable - review boot images manually")
            write_lines(review, self.output_paths['checks'] / 'deployment_shares.txt')

    def _mdt_credentials(self, client: SysvolClient, share: str) -> List[str]:
        found = []
        for path in MDT_FILES:
            content = client.read(path, share=share)
            if content:
                found.extend(f"{path}: {line}" for line in parse_mdt_ini(content))
        try:
            task_sequences = [e.get_longname() for e in client.list('Control', share=share) if e.is_directory()]
        except Exception as e:
            self.logger.debug(f"Could not list {share}/Control: {e}")
            task_sequences = []
        for ts in task_sequences[:MAX_TASK_SEQUENCES]:
            path = f"Control/{ts}/Unattend.xml"
            content = client.read(path, share=share)
            if content:
                found.extend(f"{path}: {line}" for line in parse_unattend(content))
        return found
