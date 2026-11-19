"""Shared, cached SMB access to SYSVOL / NETLOGON on a domain controller.

One SMB session per (DC, domain, user) for the whole run, supporting both
password and pass-the-hash authentication. GPO folders are listed with a
'/*' pattern: impacket's listPath uses the last path component as search
pattern, so listing 'Policies' without it only returns the folder itself.
"""

import io
from typing import Dict, Iterator, List, Optional, Tuple

from .dc import reachable_dc_hostname
from .gpttmpl import parse_gpttmpl_inf
from .registry_pol import parse_pol_file

GPTTMPL_PATH = 'Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf'
MACHINE_REGISTRY_POL = 'Machine/Registry.pol'
MAX_FILE_SIZE = 10 * 1024 * 1024


def split_hashes(hashes: Optional[str]) -> Tuple[str, str]:
    """'LM:NT' or 'NT' -> (lm, nt)."""
    if not hashes:
        return '', ''
    return tuple(hashes.split(':', 1)) if ':' in hashes else ('', hashes)


def has_credentials(username: Optional[str], password: Optional[str], hashes: Optional[str]) -> bool:
    return bool(username and (password or hashes))


class SysvolClient:
    """Reads files from SYSVOL/NETLOGON on one reachable DC, with caching."""

    _shared: Dict[tuple, 'SysvolClient'] = {}

    def __init__(self, ldap_conn, domain: str, username: str, password: Optional[str] = None,
                 hashes: Optional[str] = None, logger=None, host: Optional[str] = None):
        self.ldap = ldap_conn
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password or ''
        self.lmhash, self.nthash = split_hashes(hashes)
        self.logger = logger
        self.host = host or reachable_dc_hostname(ldap_conn, logger)
        self._conn = None
        self._gpos: Optional[List[str]] = None
        self._files: Dict[Tuple[str, str], Optional[bytes]] = {}

    @classmethod
    def shared(cls, ldap_conn, domain: str, username: str, password: Optional[str] = None,
               hashes: Optional[str] = None, logger=None) -> 'SysvolClient':
        """One client per (LDAP server, domain, user) for the whole run."""
        key = (ldap_conn.config.server, (domain or ldap_conn.config.domain).lower(), (username or '').lower())
        client = cls._shared.get(key)
        if client is None:
            client = cls(ldap_conn, domain, username, password, hashes, logger)
            cls._shared[key] = client
        return client

    # ---- connection ----
    @property
    def conn(self):
        if self._conn is None:
            from impacket.smbconnection import SMBConnection
            conn = SMBConnection(self.host, self.host)
            conn.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            self._conn = conn
        return self._conn

    def close(self):
        if self._conn is not None:
            try:
                self._conn.logoff()
            except Exception:
                pass  # session already gone - nothing to clean up
            self._conn = None

    # ---- generic file access ----
    def list(self, path: str, share: str = 'SYSVOL'):
        """Entries directly below path (excluding '.' and '..')."""
        return [e for e in self.conn.listPath(share, f"{path.rstrip('/')}/*")
                if e.get_longname() not in ('.', '..')]

    def read(self, path: str, share: str = 'SYSVOL', max_size: int = MAX_FILE_SIZE) -> Optional[bytes]:
        """File contents, or None if it doesn't exist / can't be read / is too large."""
        key = (share, path.lower())
        if key in self._files:
            return self._files[key]
        buffer = io.BytesIO()

        def write(data):
            if buffer.tell() + len(data) > max_size:
                raise ValueError("file too large")
            buffer.write(data)

        try:
            self.conn.getFile(share, path, write)
            data = buffer.getvalue()
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Could not read {share}/{path}: {e}")
            data = None
        self._files[key] = data
        return data

    def walk(self, path: str, share: str = 'SYSVOL', max_depth: int = 12) -> Iterator[str]:
        """Recursively yield file paths below path."""
        if max_depth < 0:
            return
        try:
            entries = self.list(path, share)
        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error listing {share}/{path}: {e}")
            return
        for entry in entries:
            full_path = f"{path.rstrip('/')}/{entry.get_longname()}" if path else entry.get_longname()
            if entry.is_directory():
                yield from self.walk(full_path, share, max_depth - 1)
            else:
                yield full_path

    # ---- GPO helpers ----
    @property
    def policies_path(self) -> str:
        return f"{self.domain}/Policies"

    def gpo_folders(self) -> List[str]:
        """GPO folder names ('{GUID}') in SYSVOL."""
        if self._gpos is None:
            self._gpos = [e.get_longname() for e in self.list(self.policies_path)
                          if e.is_directory() and e.get_longname().startswith('{')]
        return self._gpos

    def gpo_file(self, guid: str, relative_path: str) -> Optional[bytes]:
        return self.read(f"{self.policies_path}/{guid}/{relative_path}")

    def registry_pol(self, guid: str) -> List[tuple]:
        """Parsed Machine/Registry.pol entries of a GPO ([] if absent)."""
        content = self.gpo_file(guid, MACHINE_REGISTRY_POL)
        return parse_pol_file(content) if content else []

    def gpttmpl(self, guid: str) -> Dict[str, Dict[str, str]]:
        """Parsed Machine GptTmpl.inf of a GPO ({} if absent)."""
        content = self.gpo_file(guid, GPTTMPL_PATH)
        return parse_gpttmpl_inf(content) if content else {}
