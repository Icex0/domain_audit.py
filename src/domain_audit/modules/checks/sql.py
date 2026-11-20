"""SQL Server enumeration and checks using netexec."""

import re
import subprocess
from typing import Dict, List, Tuple
from pathlib import Path

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.netexec import report_netexec_failure
from ...utils.targets import TargetFiles, TargetScope
from ...utils.output import write_lines


class SQLChecker:
    """SQL Server enumeration via netexec."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 username: str = None, password: str = None, hashes: str = None,
                 target_scope: TargetScope = None,
                 target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_scope = target_scope or TargetScope()
        self.target_files = target_files or TargetFiles(output_paths['data'], self.target_scope, self.logger)
    
    def check_sql(self):
        """Run all SQL checks."""
        self.logger.info("---Checking SQL enumeration---")
        
        # Find computers with MSSQL SPN
        mssql_hosts = self._get_mssql_hosts()
        if not mssql_hosts:
            self.logger.info("[*] No MSSQL servers found via SPN")
            return
        
        self.logger.info(f"[*] Found {len(mssql_hosts)} MSSQL servers")
        self.logger.debug(f"[*] MSSQL hosts: {mssql_hosts}")
        
        # Check each MSSQL host
        linked_servers = []
        impersonate_privs = []
        encryption_disabled = []
        privesc_paths = []
        epa_not_required, epa_unverified = [], []
        logins = []
        
        # Collect all outputs for saving
        all_outputs = []
        
        for host in mssql_hosts:
            # Check linked servers - show output and parse
            links_output = self._run_netexec_module(host, 'enum_links')
            if links_output:
                self.logger.debug(links_output)  # Raw netexec output (debug only)
                all_outputs.append(f"=== {host} - enum_links ===")
                all_outputs.append(links_output)
                all_outputs.append("")
                links = self._parse_links_output(links_output)
                if links:
                    linked_servers.append({'host': host, 'links': links})
                # Check for encryption disabled
                if 'EncryptionReq:False' in links_output:
                    encryption_disabled.append(host)
            
            # Check impersonation - show output and parse
            imp_output = self._run_netexec_module(host, 'enum_impersonate')
            if imp_output:
                self.logger.debug(imp_output)  # Raw netexec output (debug only)
                all_outputs.append(f"=== {host} - enum_impersonate ===")
                all_outputs.append(imp_output)
                all_outputs.append("")
                users = self._parse_impersonate_output(imp_output)
                if users:
                    impersonate_privs.append({'host': host, 'users': users})
                # Check for encryption disabled (if not already found)
                if 'EncryptionReq:False' in imp_output and host not in encryption_disabled:
                    encryption_disabled.append(host)

            # Privilege escalation paths to sysadmin (enumeration only, no ACTION=privesc)
            priv_output = self._run_netexec_module(host, 'mssql_priv')
            if priv_output:
                all_outputs += [f"=== {host} - mssql_priv ===", priv_output, ""]
                path = self._parse_priv_output(priv_output)
                if path:
                    privesc_paths.append({'host': host, 'path': path})

            # Extended Protection (channel binding) - NTLM relay to MSSQL
            cbt_output = self._run_netexec_module(host, 'mssql_cbt')
            if cbt_output:
                all_outputs += [f"=== {host} - mssql_cbt ===", cbt_output, ""]
                state = self._parse_cbt_output(cbt_output)
                if state == 'not_required':
                    epa_not_required.append(host)
                elif state == 'unverified':
                    epa_unverified.append(host)

            # Login inventory (informational)
            logins_output = self._run_netexec_module(host, 'enum_logins')
            if logins_output:
                all_outputs += [f"=== {host} - enum_logins ===", logins_output, ""]
                for name, login_type, status in self._parse_logins_output(logins_output):
                    logins.append(f"{host}: {name} ({login_type}, {status})")
        
        # Save results
        if linked_servers:
            self.logger.finding(f"Found linked servers on {len(linked_servers)} MSSQL hosts")
            lines = []
            for item in linked_servers:
                lines.append(f"Host: {item['host']}")
                for link in item['links']:
                    lines.append(f"  - {link}")
                lines.append("")
            write_lines(lines, self.output_paths['findings'] / 'mssql_linked_servers.txt')
        
        if impersonate_privs:
            self.logger.finding(f"Found impersonation privileges on {len(impersonate_privs)} MSSQL hosts")
            lines = []
            for item in impersonate_privs:
                lines.append(f"Host: {item['host']}")
                lines.append("  Logins that can be impersonated (IMPERSONATE grantors):")
                for user in item['users']:
                    lines.append(f"  - {user}")
                lines.append("")
            write_lines(lines, self.output_paths['findings'] / 'mssql_impersonate_privs.txt')
        
        if encryption_disabled:
            self.logger.info("---Checking for MSSQL without encryption---")
            self.logger.finding(f"Found {len(encryption_disabled)} MSSQL hosts with encryption disabled")
            write_lines(encryption_disabled, self.output_paths['findings'] / 'mssql_encryption_disabled.txt')
        
        if privesc_paths:
            self.logger.finding(f"Current user can escalate to sysadmin on {len(privesc_paths)} MSSQL host(s): "
                                f"{', '.join(p['host'] for p in privesc_paths)}")
            lines = []
            for item in privesc_paths:
                lines.append(f"Host: {item['host']}")
                lines.extend(f"  - {step}" for step in item['path'])
                lines.append("")
            lines += ["Paths found by NetExec mssql_priv (enumeration only; nothing was changed):",
                      "- 'can impersonate: X (sysadmin)': EXECUTE AS LOGIN = 'X' gives sysadmin rights.",
                      "- 'can privesc via dbowner': the user is db_owner of a TRUSTWORTHY database owned by a",
                      "  sysadmin, so code in that database can run as sysadmin.",
                      "",
                      "Recommendation: remove IMPERSONATE permissions on privileged logins, set TRUSTWORTHY",
                      "OFF on user databases and do not let sysadmins own user databases."]
            write_lines(lines, self.output_paths['findings'] / 'mssql_privesc_sysadmin.txt')

        if epa_not_required:
            self.logger.finding(f"Extended Protection (channel binding) not required on {len(epa_not_required)} "
                                f"MSSQL host(s) - NTLM relay to MSSQL possible: {', '.join(epa_not_required)}")
            write_lines([f"  - {h}" for h in epa_not_required] + [
                "",
                "A login without a channel binding token succeeded over TLS (NetExec mssql_cbt), so",
                "Extended Protection is Off or Allowed. NTLM authentication coerced from a user or",
                "computer can be relayed to these servers (e.g. ntlmrelayx -t mssql://host) and used",
                "with that account's SQL permissions.",
                "",
                "Recommendation: set Extended Protection to Required and Force Encryption to Yes",
                "(SQL Server Configuration Manager > Protocols > Advanced / Flags)."],
                self.output_paths['findings'] / 'mssql_epa_not_required.txt')

        if epa_unverified:
            self.logger.warning(f"[!] Extended Protection could not be verified on {len(epa_unverified)} MSSQL host(s) "
                                "(encryption not forced) - check manually")
            write_lines([f"  - {h}" for h in epa_unverified] + [
                "",
                "Force Encryption is off, so channel binding cannot be tested; only service binding",
                "(Extended Protection = Required) would block NTLM relay on unencrypted connections.",
                "NetExec reports these as 'Channel Binding Token NOT REQUIRED' without testing it.",
                "Verify the Extended Protection setting in SQL Server Configuration Manager, or test",
                "a relay (ntlmrelayx -t mssql://host). Recommendation: Extended Protection Required",
                "and Force Encryption Yes."],
                self.output_paths['checks'] / 'mssql_epa_unverified.txt')

        if logins:
            self.logger.info(f"[*] {len(logins)} SQL Server login(s) visible to the current user (saved to data)")
            write_lines(["SQL Server logins visible to the current user (NetExec enum_logins). A low-privileged",
                         "login only sees its own login, sa and logins it has permissions on.", ""] + logins,
                        self.output_paths['data'] / 'mssql_logins.txt')

        # Save all netexec outputs
        if all_outputs:
            write_lines(all_outputs, self.output_paths['data'] / 'mssql_servers.txt')
    
    def _get_mssql_hosts(self) -> List[str]:
        """Find MSSQL servers via SPN enumeration and network scan results."""
        hosts = []
        spn_hosts = []
        
        # First, check network scan results for MSSQL hosts (port 1433)
        try:
            filtered_hosts = self.target_files.read('scandata_hostalive_mssql.txt', "MSSQL").targets
            for ip in filtered_hosts:
                if ip not in hosts:
                    hosts.append(ip)
            if hosts:
                self.logger.info(f"[*] Found {len(hosts)} MSSQL hosts from network scan")
        except Exception as e:
            self.logger.debug(f"Failed to read network scan MSSQL results: {e}")
        
        # Also search for MSSQL SPNs in LDAP
        try:
            query = """(&(objectCategory=computer)(servicePrincipalName=MSSQL*))"""
            results = self.ldap.query(
                search_base=self.base_dn,
                search_filter=query,
                attributes=['dNSHostName', 'servicePrincipalName']
            )
            
            hostnames = [entry.get('dNSHostName', '') for entry in results if entry.get('dNSHostName')]
            filtered_spns = self.target_scope.filter_targets(
                hostnames, logger=self.logger, label="MSSQL SPN host"
            ).targets
            for hostname in filtered_spns:
                if hostname and hostname not in hosts:
                    hosts.append(hostname)
                    spn_hosts.append(hostname)
            
            if spn_hosts:
                self.logger.info(f"[*] Found {len(spn_hosts)} additional MSSQL hosts from SPNs")
        except Exception as e:
            self.logger.debug(f"Failed to enumerate MSSQL SPNs: {e}")
        
        return hosts
    
    def _run_netexec_module(self, host: str, module: str) -> str:
        """Run a netexec module against a host."""
        cmd = [
            'netexec', 'mssql', host,
            '-u', self.username,
            '-p', self.password,
            '-M', module
        ]
        
        if self.hashes and not self.password:
            cmd = [
                'netexec', 'mssql', host,
                '-u', self.username,
                '-H', self.hashes,
                '-M', module
            ]
        
        self.logger.debug(f"[*] Running: {' '.join(cmd)}")
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=30
            )
            output = (result.stdout or '') + (result.stderr or '')
            report_netexec_failure(self.logger, f"netexec MSSQL {module} module for {host}", result)
            return output
        except subprocess.TimeoutExpired:
            self.logger.error(f"[-] netexec MSSQL {module} module timed out for {host}")
            return ""
        except FileNotFoundError:
            self.logger.error("[-] netexec not found on system")
            return ""
        except Exception as e:
            self.logger.error(f"[-] Error running netexec MSSQL {module} module for {host}: {e}")
            return ""
    
    @staticmethod
    def _module_messages(output: str) -> List[Tuple[str, str]]:
        """Split netexec output into (status, message) pairs.

        NetExec prints module lines as
        '<MODULE> <ip> <port> <hostname> [*|+|-] <message>' (nxc/logger.py),
        so the message has to be taken from after the status marker.
        """
        messages = []
        for line in re.sub(r'\x1b\[[0-9;]*m', '', output).split('\n'):
            match = re.search(r'\[([*+-])\] (.*)$', line)
            if match:
                messages.append((match.group(1), match.group(2).strip()))
        return messages

    def _parse_links_output(self, output: str) -> List[str]:
        """Parse enum_links output for linked servers.

        NetExec prints a 'Linked servers found:' block with '- <server>' entries
        (sys.servers), and as sysadmin a second block with 'Linked server: <name>'
        followed by '- Local login: ...' / '- Remote login: ...' (sp_helplinkedsrvlogin).
        """
        links: List[str] = []
        mappings: List[str] = []
        in_block = False
        current = None
        login = {}

        def flush_mapping():
            if current and login:
                mappings.append(
                    f"{current}: local login {login.get('Local', '?')} -> remote login {login.get('Remote', '?')}"
                )

        for status, msg in self._module_messages(output):
            if msg == 'Linked servers found:':
                flush_mapping()
                in_block, current, login = True, None, {}
                continue
            if not in_block:
                continue
            if status != '*':
                flush_mapping()
                in_block, current, login = False, None, {}
                continue

            server_match = re.match(r'Linked server: (.+)$', msg)
            login_match = re.match(r'- (Local|Remote) login: (.*)$', msg)
            item_match = re.match(r'- (.+)$', msg)
            if server_match:
                flush_mapping()
                current, login = server_match.group(1).strip(), {}
                if current not in links:
                    links.append(current)
            elif login_match and current:
                if login_match.group(1) in login:
                    # sp_helplinkedsrvlogin can list several logins per server
                    flush_mapping()
                    login = {}
                login[login_match.group(1)] = login_match.group(2).strip()
            elif item_match:
                name = item_match.group(1).strip()
                if name and name not in links:
                    links.append(name)
        flush_mapping()

        return links + [f"login mapping - {m}" for m in mappings]

    def _parse_impersonate_output(self, output: str) -> List[str]:
        """Parse enum_impersonate output.

        NetExec's query selects the *grantor* of IMPERSONATE permissions, i.e. the
        logins that can be impersonated, despite its 'Users with impersonation
        rights:' header.
        """
        users: List[str] = []
        in_block = False
        for status, msg in self._module_messages(output):
            if msg == 'Users with impersonation rights:':
                in_block = True
                continue
            if not in_block:
                continue
            item_match = re.match(r'- (.+)$', msg)
            if status == '*' and item_match:
                user = item_match.group(1).strip()
                if user and user not in users:
                    users.append(user)
            else:
                in_block = False
        return users

    def _parse_priv_output(self, output: str) -> List[str]:
        """Parse mssql_priv (enum_priv) output into a privesc path.

        Returns the impersonation steps plus the final step when a path to sysadmin
        exists ('[+] X can impersonate: Y (sysadmin)', '[+] X can privesc via
        dbowner', ...), or [] when there is none or the user is already sysadmin.
        """
        steps: List[str] = []
        found = False
        for status, msg in self._module_messages(output):
            if re.search(r' can impersonate: .+$', msg) or msg.endswith(' can privesc via dbowner'):
                steps.append(msg)
                if status == '+':
                    found = True
        return steps if found else []

    @staticmethod
    def _parse_cbt_output(output: str) -> str:
        """Classify mssql_cbt output: 'not_required', 'required', 'unverified' or ''.

        The module prints highlight lines without a status marker. Without forced
        encryption it reports 'NOT REQUIRED' without testing; Extended Protection
        can then still block relay through service binding, so that is unverified.
        """
        text = re.sub(r'\x1b\[[0-9;]*m', '', output)
        if 'Connection successful: Channel Binding Token NOT REQUIRED' in text:
            return 'not_required'
        if 'Channel Binding Token REQUIRED' in text and 'NOT REQUIRED' not in text:
            return 'required'
        if 'TLS not required' in text:
            return 'unverified'
        return ''

    @staticmethod
    def _parse_logins_output(output: str) -> List[Tuple[str, str, str]]:
        """Parse enum_logins rows ('<name> <type> ENABLED|DISABLED') after its header."""
        rows: List[Tuple[str, str, str]] = []
        offset = None
        for line in re.sub(r'\x1b\[[0-9;]*m', '', output).split('\n'):
            if offset is None:
                if 'Login Name' in line and 'Status' in line:
                    offset = line.index('Login Name')
                continue
            row = line[offset:].strip()
            if not row or set(row) <= set('- '):
                continue
            match = re.match(r'(.+?)\s+(SQL User|Domain User|Local User|Windows Group|Certificate Login|'
                             r'Asymmetric Key Login|\S+)\s+(ENABLED|DISABLED)$', row)
            if match:
                rows.append((match.group(1).strip(), match.group(2), match.group(3)))
        return rows
