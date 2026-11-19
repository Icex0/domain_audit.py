"""WSUS security checks - detect HTTP WSUS which is vulnerable to MITM attacks."""

import struct
from urllib.parse import urlparse
from typing import Dict, List, Optional
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.registry_pol import parse_pol_file
from ...utils.sysvol import SysvolClient, has_credentials


class WSUSChecker:
    """Check WSUS configuration for HTTP usage which enables MITM attacks."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 server: str = None, username: str = None, password: str = None,
                 domain: str = None, hashes: str = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.server = server or ldap_conn.config.server
        self.username = username
        self.password = password
        self.hashes = hashes
        self.domain = domain or ldap_conn.config.domain
    
    def check_wsus(self):
        """Check WSUS configuration for HTTP usage (vulnerable to MITM)."""
        self.logger.info("---Checking WSUS configuration for HTTP usage---")
        
        if not has_credentials(self.username, self.password, self.hashes):
            self.logger.warning("[!] WSUS check requires SMB credentials")
            return
        
        try:
            sysvol = SysvolClient.shared(self.ldap, self.domain, self.username, self.password, self.hashes, self.logger)
            wsus_policies = []
            for guid in sysvol.gpo_folders():
                info = self._parse_wsus_entries(sysvol.registry_pol(guid), guid)
                if info:
                    wsus_policies.append(info)
            
            url_policies = [p for p in wsus_policies if p['url']]
            if not url_policies:
                self.logger.success("[+] No WSUS policies found in SYSVOL")
                return
            
            try:
                self._report_effective(wsus_policies)
            except Exception as e:
                self.logger.warning(f"[!] Could not evaluate where the WSUS GPOs apply ({e}) - reporting per GPO")
                self._report_per_gpo(url_policies)
                
        except Exception as e:
            self.logger.error(f"[-] Error checking WSUS configuration: {e}")
    
    def _report_effective(self, wsus_policies: List[Dict]):
        """Report WSUS settings per computer, taking GPO links, inheritance,
        enforcement and security filtering into account (utils.gpo_scope).

        A computer is exposed when its effective WUServer is an http:// URL and
        its effective UseWUServer is 1 (default 0 = WSUS not used).
        """
        from ...utils.gpo_scope import GPOScope
        
        url_values = {p['gpo_name'].upper(): p['url'] for p in wsus_policies if p['url']}
        use_values = {p['gpo_name'].upper(): p['use_wu_server'] for p in wsus_policies if p['use_wu_server'] is not None}
        
        scope = GPOScope(self.ldap, self.logger)
        computers = self.ldap.query(
            search_base=self.base_dn,
            search_filter='(&(objectClass=computer)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
            attributes=['sAMAccountName', 'distinguishedName', 'objectSid', 'primaryGroupID', 'userAccountControl']
        )
        
        by_url: Dict[str, List[str]] = {}
        not_used: List[str] = []
        verify: List[str] = []
        for computer in computers:
            name = computer.get('sAMAccountName') or computer['distinguishedName']
            url_result = scope.effective_value(computer, url_values)
            if url_result.status == 'not_configured':
                continue
            if url_result.status != 'configured':
                verify.append(f"{name}: WUServer {url_result.status} - {url_result.reason} ({', '.join(url_result.gpos)})")
                continue
            use_result = scope.effective_value(computer, use_values) if use_values else None
            if use_result is not None and use_result.status in ('conflict', 'uncertain'):
                verify.append(f"{name}: UseWUServer {use_result.status} - {use_result.reason} ({', '.join(use_result.gpos)})")
                continue
            if use_result is None or use_result.status == 'not_configured':
                # Default is 0 (not used), but UseWUServer can also come from local
                # policy (e.g. Configuration Manager) - then the GPO URL is used.
                if urlparse(url_result.value).scheme.lower() == 'http':
                    verify.append(f"{name}: http WUServer {url_result.value} via GPO, but no GPO sets UseWUServer "
                                  "(default 0 = not used, unless set locally/by ConfigMgr)")
                continue
            if use_result.value == 1:
                by_url.setdefault(url_result.value, []).append(name)
            else:
                not_used.append(f"{name}: WUServer {url_result.value} set but UseWUServer={use_result.value} (WSUS not used)")
        
        gpo_names = {guid: info.name for guid, info in scope.gpos.items()}
        def gpos_for(url):
            return ', '.join(sorted(gpo_names.get(g, g) for g, u in url_values.items() if u == url))
        
        http_urls = {u: c for u, c in by_url.items() if urlparse(u).scheme.lower() == 'http'}
        https_urls = {u: c for u, c in by_url.items() if urlparse(u).scheme.lower() == 'https'}
        
        if http_urls:
            total = sum(len(c) for c in http_urls.values())
            self.logger.finding(f"{total} computers get Windows updates from WSUS over HTTP (vulnerable to MITM)")
            lines = []
            for url, names in sorted(http_urls.items()):
                lines.append(f"URL: {url} (port {urlparse(url).port or 80})")
                lines.append(f"  GPO(s): {gpos_for(url)}")
                lines.append(f"  Effective on {len(names)} computers (UseWUServer=1):")
                lines.extend(f"    {n}" for n in sorted(names))
                lines.append("  VULNERABLE: WSUS over HTTP allows MITM attacks (see WSUSpect/wsuks)")
                lines.append("")
            write_lines(lines, self.output_paths['findings'] / 'wsus_http_vulnerable.txt')
        
        if https_urls:
            self.logger.success(f"[+] {sum(len(c) for c in https_urls.values())} computers use WSUS over HTTPS")
            write_lines([f"{u} ({gpos_for(u)}): {len(c)} computers" for u, c in sorted(https_urls.items())],
                        self.output_paths['data'] / 'wsus_https_policies.txt')
        
        if not http_urls:
            self.logger.success("[+] No computers get updates from WSUS over HTTP via GPO")
            unused_http = [p for p in wsus_policies if p['scheme'] == 'http']
            if unused_http and not verify:
                self.logger.info(f"[*] {len(unused_http)} GPO(s) set an http:// WSUS URL but it isn't effective on any computer "
                                 "(not linked, filtered, overridden or UseWUServer=0)")
        
        if not_used:
            write_lines(not_used, self.output_paths['data'] / 'wsus_url_not_used.txt')
        if verify:
            self.logger.warning(f"[!] WSUS GPO scope couldn't be determined for {len(verify)} computers - verify manually")
            write_lines(verify, self.output_paths['checks'] / 'wsus_verify.txt')
    
    def _report_per_gpo(self, url_policies: List[Dict]):
        """Fallback when GPO scope can't be evaluated: report each GPO's URL."""
        active = [p for p in url_policies if p['use_wu_server'] != 0]
        for policy in url_policies:
            if policy['use_wu_server'] == 0:
                self.logger.info(f"[*] {policy['gpo_name']}: WUServer {policy['url']} is set but UseWUServer=0 (not used)")
        http_policies = [p for p in active if p['scheme'] == 'http']
        https_policies = [p for p in active if p['scheme'] == 'https']
        
        if http_policies:
            self.logger.finding(f"{len(http_policies)} WSUS policies use HTTP (vulnerable to MITM) - GPO scope not evaluated")
            findings = []
            for policy in http_policies:
                findings.append(
                    f"GPO: {policy['gpo_name']}\n"
                    f"  URL: {policy['url']} (port {policy['port']})\n"
                    + ("  Note: UseWUServer isn't set in this GPO - verify it's set to 1 by another GPO\n"
                       if policy['use_wu_server'] is None else "")
                    + "  VULNERABLE: WSUS over HTTP allows MITM attacks (see WSUSpect/wsuks)"
                )
            write_lines(findings, self.output_paths['findings'] / 'wsus_http_vulnerable.txt')
        if https_policies:
            self.logger.success(f"[+] {len(https_policies)} WSUS policies use HTTPS (not vulnerable)")
            write_lines([f"GPO: {p['gpo_name']} - {p['url']}" for p in https_policies],
                        self.output_paths['data'] / 'wsus_https_policies.txt')
        if not http_policies:
            self.logger.success("[+] No active WSUS policies use HTTP")
    
    WU_KEY = 'software\\policies\\microsoft\\windows\\windowsupdate'
    AU_KEY = WU_KEY + '\\au'

    def _parse_wsus_from_pol(self, content: bytes, gpo_name: str) -> Optional[Dict]:
        """Parse raw Registry.pol content (see _parse_wsus_entries)."""
        return self._parse_wsus_entries(parse_pol_file(content), gpo_name)

    def _parse_wsus_entries(self, entries, gpo_name: str) -> Optional[Dict]:
        """Parse Registry.pol content and extract WSUS server configuration.
        
        Looks for (registry keys and value names are case-insensitive):
        - Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer:
          URL like http://wsus.domain.com:8530 or https://wsus.domain.com:8531
        - Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU\\UseWUServer:
          clients only use WUServer when this is 1
        """
        url = None
        use_wu_server = None
        
        for key, value_name, reg_type, size, data in entries:
            key_lower = key.lower().rstrip('\\')
            value_lower = value_name.lower()
            if key_lower == self.WU_KEY and value_lower == 'wuserver' and reg_type in (1, 2):
                url = data.decode('utf-16-le', errors='ignore').rstrip('\x00').strip()
            elif key_lower == self.AU_KEY and value_lower == 'usewuserver':
                if reg_type == 4 and len(data) >= 4:
                    use_wu_server = struct.unpack('<I', data[:4])[0]
            elif key_lower == self.AU_KEY and value_lower == '**del.usewuserver':
                use_wu_server = 0  # value deleted by this GPO
        
        if not url and use_wu_server is None:
            return None
        
        scheme = host = port = None
        if url:
            try:
                parsed = urlparse(url)
                scheme = (parsed.scheme or '').lower()
                host = parsed.hostname
                # A URL without a port uses the scheme default (80/443); WSUS's
                # 8530/8531 only apply when written in the URL.
                port = parsed.port or (443 if scheme == 'https' else 80)
            except ValueError:
                scheme = None
            if scheme not in ('http', 'https') or not host:
                url = scheme = host = port = None
                if use_wu_server is None:
                    return None
        
        return {
            'gpo_name': gpo_name,
            'scheme': scheme,
            'host': host,
            'port': port,
            'url': url,
            'use_wu_server': use_wu_server,
        }
