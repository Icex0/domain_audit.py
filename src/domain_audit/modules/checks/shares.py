"""SYSVOL and NETLOGON credential checks.

SYSVOL and NETLOGON are replicated between DCs, so one reachable DC is scanned
via the shared utils.sysvol client.
"""

from pathlib import Path
from typing import Dict

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
import re

from ...utils.gpp import find_cpasswords, find_autologon, find_keyword_hits, find_keyword_lines
from ...utils.sysvol import SysvolClient, has_credentials
from ...config import SYSVOL_PASSWORD_KEYWORDS, NETLOGON_PASSWORD_KEYWORDS

# Script/text files searched line by line (NETLOGON, and GPO logon/startup scripts in SYSVOL)
SCRIPT_EXTENSIONS = ('.bat', '.cmd', '.ps1', '.psm1', '.vbs', '.js', '.kix', '.txt', '.ini')
NETLOGON_TEXT_EXTENSIONS = SCRIPT_EXTENSIONS


class FileShareChecker:
    """Group Policy Preferences passwords and password keywords on SYSVOL/NETLOGON."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None,
                 username: str = None, password: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes

    def check_shares(self):
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning("[!] SYSVOL/NETLOGON checks require SMB credentials")
            return
        self._check_sysvol_passwords()
        self._check_netlogon_passwords()

    def _gpo_names(self) -> Dict[str, str]:
        """GPO GUID (upper case, with braces) -> display name."""
        try:
            gpos = self.ldap.query(self.ldap.config.base_dn, '(objectClass=groupPolicyContainer)',
                                   ['cn', 'displayName'])
        except Exception as e:
            self.logger.debug(f"Could not read GPO names: {e}")
            return {}
        return {str(g.get('cn', '')).upper(): str(g.get('displayName', '')) for g in gpos if g.get('cn')}

    @staticmethod
    def _gpo_label(file_path: str, names: Dict[str, str]) -> str:
        match = re.search(r'\{[0-9A-Fa-f-]{36}\}', file_path)
        if not match:
            return file_path
        name = names.get(match.group(0).upper())
        return f"{file_path} (GPO: {name})" if name else file_path

    def _sysvol(self) -> SysvolClient:
        return SysvolClient.shared(self.ldap, self.domain, self.username, self.password, self.hashes, self.logger)

    def _check_sysvol_passwords(self):
        """GPP cpasswords (decrypted), GPP autologon passwords and password keywords in
        the XML files of all GPO folders. GPP files sit several levels deep, e.g.
        Policies/{GUID}/Machine/Preferences/Groups/Groups.xml, so the folder is walked
        recursively."""
        self.logger.info("---Checking SYSVOL for passwords---")
        self.logger.info("[*] This might take a while")

        try:
            sysvol = self._sysvol()
            gpo_names = self._gpo_names()
            gpp_findings, autologon_findings, keyword_hits = [], [], []
            keyword_files = 0
            xml_count = script_count = 0
            for file_path in sysvol.walk(sysvol.policies_path):
                lower_path = file_path.lower()
                if lower_path.endswith(SCRIPT_EXTENSIONS) and lower_path.rsplit('/', 1)[-1] != 'gpt.ini':
                    # GPO logon/logoff/startup/shutdown scripts (e.g. User/Scripts/Logon/map.bat)
                    script_count += 1
                    content = sysvol.read(file_path)
                    hits = find_keyword_lines(content, SYSVOL_PASSWORD_KEYWORDS) if content else []
                    if hits:
                        keyword_files += 1
                        keyword_hits.append(self._gpo_label(file_path, gpo_names))
                        keyword_hits.extend(f"  {hit}" for hit in hits)
                        keyword_hits.append("")
                    continue
                if not lower_path.endswith('.xml'):
                    continue
                xml_count += 1
                content = sysvol.read(file_path)
                if not content:
                    continue

                found_credentials = False
                for entry in find_cpasswords(content):
                    password = entry['password'] or f"<could not decrypt: {entry['cpassword']}>"
                    gpp_findings.append(f"{file_path}: user '{entry['user'] or '?'}' password '{password}'")
                    found_credentials = True
                if file_path.lower().endswith('registry.xml'):
                    for entry in find_autologon(content):
                        user = f"{entry['domain']}\\{entry['user']}" if entry['domain'] else (entry['user'] or '?')
                        autologon_findings.append(f"{file_path}: autologon user '{user}' password '{entry['password']}'")
                        found_credentials = True
                if found_credentials:
                    continue  # already reported with the actual credentials; skip the keyword hit

                hits = find_keyword_hits(content, SYSVOL_PASSWORD_KEYWORDS)
                if hits:
                    keyword_files += 1
                    keyword_hits.append(self._gpo_label(file_path, gpo_names))
                    keyword_hits.extend(f"  {hit}" for hit in hits)
                    keyword_hits.append("")

            self.logger.info(f"[*] Scanned {xml_count} XML files and {script_count} script files in SYSVOL of {sysvol.host}")

            if gpp_findings:
                self.logger.finding(f"{len(gpp_findings)} Group Policy Preferences passwords (cpassword) found in SYSVOL")
                write_lines(gpp_findings, self.output_paths['findings'] / 'sysvol_gpp_passwords.txt')
            else:
                self.logger.success("[+] No Group Policy Preferences passwords (cpassword) found in SYSVOL")

            if autologon_findings:
                self.logger.finding(f"{len(autologon_findings)} cleartext autologon password(s) in Group Policy Preferences (Registry.xml)")
                write_lines(autologon_findings, self.output_paths['findings'] / 'sysvol_gpp_autologon.txt')
            else:
                self.logger.success("[+] No Group Policy Preferences autologon passwords found in SYSVOL")

            if keyword_hits:
                self.logger.warning(f"[!] {keyword_files} SYSVOL file(s) contain password keywords or credentials - "
                                    "review the matched values in sysvol_passwords.txt")
                write_lines(["Password keywords and credential command lines in SYSVOL (GPP XML values and GPO",
                             "scripts; GPP schema attributes such as bypassErrors and empty cpassword are",
                             "ignored). Review each value:", ""] + keyword_hits,
                            self.output_paths['checks'] / 'sysvol_passwords.txt')
        except Exception as e:
            self.logger.error(f"[-] Error checking SYSVOL: {e}")

    def _check_netlogon_passwords(self):
        """Password keywords in NETLOGON file names and in script/text files."""
        self.logger.info("---Checking NETLOGON for passwords---")
        self.logger.info("[*] This might take a while")

        try:
            sysvol = self._sysvol()
            findings = []
            for full_path in sysvol.walk('', share='NETLOGON'):
                name_lower = full_path.rsplit('/', 1)[-1].lower()
                for keyword in NETLOGON_PASSWORD_KEYWORDS:
                    if keyword in name_lower:
                        findings.append(f"Suspicious filename '{full_path}' (matched '{keyword}')")
                        break
                if name_lower.endswith(NETLOGON_TEXT_EXTENSIONS):
                    content = sysvol.read(full_path, share='NETLOGON')
                    if not content:
                        continue
                    hits = find_keyword_lines(content, NETLOGON_PASSWORD_KEYWORDS)
                    if hits:
                        findings.append(f"{full_path}:")
                        findings.extend(f"  {hit}" for hit in hits)
                        findings.append("")

            if findings:
                self.logger.warning(f"[!] Possible passwords found in NETLOGON of {sysvol.host}")
                write_lines(findings, self.output_paths['checks'] / 'netlogon_passwords.txt')
                self.logger.warning("[!] Please manually check NETLOGON for passwords")
            else:
                self.logger.success(f"[+] No obvious passwords in NETLOGON of {sysvol.host}")
        except Exception as e:
            self.logger.error(f"[-] Error checking NETLOGON: {e}")
