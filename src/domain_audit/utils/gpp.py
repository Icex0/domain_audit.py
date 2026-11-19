"""Group Policy Preferences (GPP) cpassword extraction and decryption.

GPP items (Groups.xml, Services.xml, ScheduledTasks.xml, DataSources.xml,
Drives.xml, Printers.xml) can store credentials in a 'cpassword' attribute,
encrypted with an AES-256 key that Microsoft published in [MS-GPPREF] 2.2.1.1.4.
Anyone who can read SYSVOL can decrypt them (MS14-025).
"""

import base64
import re
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional

from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# [MS-GPPREF] 2.2.1.1.4 Password Encryption
GPP_AES_KEY = bytes.fromhex('4e9906e8fcb66cc9faf49310620ffee8f496e806cc057990209b09a433b66c1b')

# Attributes that hold the account name, depending on the GPP item type
_USER_ATTRIBUTES = ('userName', 'accountName', 'runAs', 'username', 'newName')


def decrypt_cpassword(cpassword: str) -> Optional[str]:
    """Decrypt a GPP cpassword value. Returns None if it can't be decrypted."""
    if not cpassword:
        return None
    try:
        value = cpassword + '=' * (-len(cpassword) % 4)
        cipher = AES.new(GPP_AES_KEY, AES.MODE_CBC, b'\x00' * 16)
        plain = unpad(cipher.decrypt(base64.b64decode(value)), AES.block_size)
        return plain.decode('utf-16-le')
    except Exception:
        return None


def _decode(content: bytes) -> str:
    if content.startswith((b'\xff\xfe', b'\xfe\xff')):
        return content.decode('utf-16', errors='ignore')
    return content.decode('utf-8-sig', errors='ignore')


def find_cpasswords(content: bytes) -> List[Dict[str, str]]:
    """Return every non-empty cpassword in a GPP XML file.

    Each result has 'user', 'cpassword' and 'password' (decrypted, or '' if
    decryption failed).
    """
    text = _decode(content)
    results = []

    try:
        root = ET.fromstring(text)
        elements = [el for el in root.iter() if el.attrib.get('cpassword')]
        for el in elements:
            user = next((el.attrib[a] for a in _USER_ATTRIBUTES if el.attrib.get(a)), '')
            cpassword = el.attrib['cpassword']
            results.append({
                'user': user,
                'cpassword': cpassword,
                'password': decrypt_cpassword(cpassword) or '',
            })
        return results
    except ET.ParseError:
        pass

    # Fallback for malformed XML: regex over each element's attributes
    for tag in re.findall(r'<[^>]*\bcpassword="[^"]+"[^>]*>', text):
        cpassword = re.search(r'\bcpassword="([^"]+)"', tag).group(1)
        user = ''
        for attr in _USER_ATTRIBUTES:
            match = re.search(rf'\b{attr}="([^"]*)"', tag)
            if match and match.group(1):
                user = match.group(1)
                break
        results.append({
            'user': user,
            'cpassword': cpassword,
            'password': decrypt_cpassword(cpassword) or '',
        })
    return results


def find_autologon(content: bytes) -> List[Dict[str, str]]:
    """Return autologon credentials from a GPP Registry.xml.

    GPP registry items for Winlogon AutoAdminLogon store DefaultPassword in
    cleartext (no cpassword encryption). Items are <Properties name=".."
    value=".."/> elements; values are grouped per Registry.xml file.
    Returns [{'user', 'domain', 'password'}] when a non-empty DefaultPassword exists.
    """
    text = _decode(content)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return []
    values: Dict[str, List[str]] = {}
    for el in root.iter():
        if el.tag.split('}')[-1] != 'Properties':
            continue
        name = (el.attrib.get('name') or '').lower()
        if name in ('defaultpassword', 'defaultusername', 'defaultdomainname'):
            values.setdefault(name, []).append(el.attrib.get('value', ''))
    passwords = [p for p in values.get('defaultpassword', []) if p]
    if not passwords:
        return []
    users = values.get('defaultusername', []) or ['']
    domains = values.get('defaultdomainname', []) or ['']
    return [{'user': users[min(i, len(users) - 1)], 'domain': domains[min(i, len(domains) - 1)], 'password': pw}
            for i, pw in enumerate(passwords)]


# GPP schema attributes whose *name* contains a keyword but that never hold a
# secret (bypassErrors="1", subAuthority="RID_ADMIN", logonType="Password", ...).
# cpassword is handled by find_cpasswords; an empty one is the schema default.
_BENIGN_ATTRIBUTES = {'bypasserrors', 'cpassword', 'subauthority', 'logontype', 'nochange', 'changelogon'}
# Substrings that contain a keyword without meaning "password" ('pass' in bypass,
# 'auth' in Authenticated Users/author, 'ww' in www).
_BENIGN_SUBSTRINGS = ('bypass', 'authenticated users', 'author', 'www', 'passive', 'compass')
# Values that only mean on/off
_FLAG_VALUES = {'', '0', '1', 'true', 'false', 'yes', 'no'}


# Command lines that carry a credential without a password keyword next to it.
_CREDENTIAL_PATTERNS = [
    ("net use /user", re.compile(r'\bnet(?:\.exe)?\s+use\b[^\r\n]*/u(?:ser)?:', re.I)),
    ("net user <name> <password>", re.compile(r'\bnet(?:\.exe)?\s+user\s+\S+\s+(?![/*])\S+', re.I)),
    ("ConvertTo-SecureString -AsPlainText", re.compile(r'-AsPlainText\b', re.I)),
    ("PSCredential", re.compile(r'\bPSCredential\b', re.I)),
    ("schtasks /rp", re.compile(r'\bschtasks(?:\.exe)?\b[^\r\n]*\s/rp\s', re.I)),
    ("psexec -p", re.compile(r'\bpsexec(?:64)?(?:\.exe)?\b[^\r\n]*\s-p\s', re.I)),
    # VBScript MapNetworkDrive(drive, path, persistent, user, password)
    ("MapNetworkDrive with password", re.compile(r'\bMapNetworkDrive\b(?:[^,\r\n]*,){4}\s*\S', re.I)),
    ("sqlcmd/osql -P", re.compile(r'\b(?:sqlcmd|osql)(?:\.exe)?\b[^\r\n]*\s-P\s', re.I)),
]


def _credential_pattern(value: str) -> Optional[str]:
    return next((label for label, pattern in _CREDENTIAL_PATTERNS if pattern.search(value)), None)


def _match(value: str, keywords) -> Optional[str]:
    """Matched keyword ('pass') or credential pattern ('pattern: net use /user')."""
    keyword = _keyword_in(value, keywords)
    if keyword:
        return keyword
    label = _credential_pattern(value)
    return f"pattern: {label}" if label else None


def _keyword_in(value: str, keywords) -> Optional[str]:
    lower = value.lower()
    for benign in _BENIGN_SUBSTRINGS:
        lower = lower.replace(benign, ' ')
    return next((kw for kw in keywords if kw in lower), None)


def _short(value: str, limit: int = 160) -> str:
    value = ' '.join(value.split())
    return value if len(value) <= limit else value[:limit] + '...'


def find_keyword_hits(content: bytes, keywords) -> List[str]:
    """Return readable keyword hits in a GPP XML file, with the matching value.

    Matches attribute values and element text, plus attribute *names* that
    contain a keyword when they hold a real value (not a GPP schema flag or an
    empty cpassword). Each hit names the GPP item (e.g. Drive "H:") so it can be
    judged without opening the file.
    """
    text = _decode(content)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return find_keyword_lines(content, keywords)

    parents = {child: parent for parent in root.iter() for child in parent}
    hits, seen = [], set()

    def item_label(el) -> str:
        """The GPP item (Drive "H:", TaskV2 "Backup", ...) an element belongs to."""
        item = el
        while item is not None and (item.tag.split('}')[-1] == 'Properties' or 'name' not in item.attrib):
            item = parents.get(item)
        if item is None:
            return el.tag.split('}')[-1]
        return f'{item.tag.split("}")[-1]} "{item.attrib["name"]}"'

    for el in root.iter():
        # A GPP item's name/status only repeat its Properties (reported there)
        has_properties = any(child.tag.split('}')[-1] == 'Properties' for child in el)
        for attr, value in el.attrib.items():
            attr_lower = attr.lower()
            if attr_lower in _BENIGN_ATTRIBUTES or (has_properties and attr_lower in ('name', 'status')):
                continue
            keyword = _match(value, keywords)
            if not keyword and value.strip().lower() not in _FLAG_VALUES:
                keyword = _keyword_in(attr, keywords)
            if keyword:
                hit = f"{item_label(el)}: {attr}=\"{_short(value)}\""
                if attr_lower == 'name' and 'value' in el.attrib:  # registry item: show the data too
                    hit += f" value=\"{_short(el.attrib['value'])}\""
                hit += f" (matched {keyword!r})"
                if hit not in seen:
                    seen.add(hit)
                    hits.append(hit)
        if el.text and el.text.strip():
            keyword = _match(el.text, keywords)
            if keyword:
                hit = f"{item_label(el)}: text \"{_short(el.text)}\" (matched {keyword!r})"
                if hit not in seen:
                    seen.add(hit)
                    hits.append(hit)
    return hits


def find_keyword_lines(content: bytes, keywords, max_lines: int = 20) -> List[str]:
    """Return 'line N: <line>' for lines of a text file that contain a keyword."""
    hits = []
    for number, line in enumerate(_decode(content).splitlines(), 1):
        keyword = _match(line, keywords)
        if keyword:
            hits.append(f"line {number}: {_short(line.strip())} (matched {keyword!r})")
            if len(hits) >= max_lines:
                hits.append("... (more matches, truncated)")
                break
    return hits
