"""Enforced SMB signing bypass via cross-user re-authentication (NetExec reauth_swap).

An SMB server that lets a *different* user re-authenticate on an existing
session allows an NTLM relay to keep a session under a signing key the attacker
controls, defeating enforced SMB signing (Blackfield, "Defeating enforced SMB
signing"). Patched servers only allow same-user re-authentication and refuse the
swap with ACCESS_DENIED. According to the researcher Microsoft fixed this in the
September 2026 updates (CVE-2026-69676, published by Microsoft as "Windows
Kerberos Remote Code Execution Vulnerability"). The fix is feature-flagged, so it
cannot be derived from the build number and is tested live: NetExec's
reauth_swap module opens a new session and re-authenticates as a second account.

The probe causes one real NTLM logon of the second account per host; a wrong
password raises its badPwdCount on every host. The account is therefore first
validated against a single host before the rest is probed.
"""

import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines
from ...utils.targets import TargetFiles, TargetScope

MODULE = 'reauth_swap'
_LINE = re.compile(r'^REAUTH_SWAP\s+(\S+)\s+\d+\s+(\S+)\s+(.*)$')
_STOP_MARKERS = ('LOGON_FAILURE', 'ACCOUNT_LOCKED_OUT', 'must differ', 'requires a second account',
                 'requires PROBE_PASS')


def parse_reauth_output(output: str) -> Dict[str, List[Tuple[str, str, str]]]:
    """Group reauth_swap results: {'vulnerable'|'not_vulnerable'|'inconclusive'|'stop': [(ip, host, msg)]}."""
    results: Dict[str, List[Tuple[str, str, str]]] = {
        'vulnerable': [], 'not_vulnerable': [], 'inconclusive': [], 'stop': []}
    for line in re.sub(r'\x1b\[[0-9;]*m', '', output).split('\n'):
        match = _LINE.match(line.strip())
        if not match:
            continue
        ip, host, msg = match.groups()
        msg = re.sub(r'^\[[*+-]\]\s*', '', msg).strip()
        if msg.startswith('VULNERABLE'):
            results['vulnerable'].append((ip, host, msg))
        elif msg.startswith('not vulnerable'):
            results['not_vulnerable'].append((ip, host, msg))
        elif any(marker in msg for marker in _STOP_MARKERS):
            results['stop'].append((ip, host, msg))
        elif msg.startswith(('inconclusive', 'could not probe')):
            results['inconclusive'].append((ip, host, msg))
    return results


class SMBReauthChecker:
    """Runs NetExec reauth_swap against SMB hosts that enforce signing."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path], domain: str = None,
                 username: str = None, password: str = None, hashes: str = None,
                 probe_user: str = None, probe_password: str = None, probe_hash: str = None,
                 target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain or ldap_conn.config.domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.probe_user = probe_user
        self.probe_password = probe_password
        self.probe_hash = probe_hash.split(':')[-1] if probe_hash else None
        self.target_files = target_files or TargetFiles(output_paths['data'], TargetScope(), self.logger)

    def check_reauth_swap(self):
        self.logger.info("---Checking for enforced SMB signing bypass (cross-user re-authentication)---")
        if not self.probe_user or not (self.probe_password or self.probe_hash):
            self.logger.info("[*] Skipped: needs a second account (--probe-user with --probe-pass or --probe-hash)")
            return
        if self.probe_user.lower() == (self.username or '').lower():
            self.logger.error("[-] --probe-user must differ from --username (a same-user re-auth always succeeds)")
            return
        if not self._module_available():
            self.logger.warning("[!] NetExec module reauth_swap not found - install NetExec from main "
                                "(pipx install --force git+https://github.com/Pennyw0rth/NetExec)")
            return
        hosts = self.target_files.read_discovered('scandata_hostalive_smb.txt', "SMB").targets
        if not hosts:
            return

        # Validate the probe account on one host first: a wrong password would
        # otherwise raise its badPwdCount once for every host.
        first = self.ldap.config.server if self.ldap.config.server in hosts else hosts[0]
        output = self._run([first])
        results = parse_reauth_output(output)
        if results['stop']:
            for _, host, msg in results['stop']:
                self.logger.error(f"[-] {host}: {msg}")
            self.logger.error("[-] Stopped before probing other hosts - check --probe-user/--probe-pass")
            return
        if not any(results.values()):
            self.logger.warning(f"[!] No reauth_swap result from {first} (login failed or signing not enforced); "
                                "continuing with the other hosts")

        rest = [h for h in hosts if h != first]
        if rest:
            output += '\n' + self._run(rest)
            results = parse_reauth_output(output)
        write_lines(output.split('\n'), self.output_paths['data'] / 'netexec_reauth_swap.txt')

        if results['stop']:
            for _, host, msg in results['stop']:
                self.logger.error(f"[-] {host}: {msg}")

        vulnerable = sorted(set((ip, host) for ip, host, _ in results['vulnerable']))
        if vulnerable:
            self.logger.finding(f"{len(vulnerable)} host(s) allow a cross-user SMB re-authentication swap "
                                f"(enforced SMB signing bypassable): {', '.join(h for _, h in vulnerable)}")
            write_lines([f"{ip} - {host}" for ip, host in vulnerable] + [
                "",
                "These hosts enforce SMB signing but accept a re-authentication as a different user on an",
                "existing SMB session (tested live with NetExec reauth_swap and a second account). Patched",
                "servers refuse this with ACCESS_DENIED. The behaviour lets an NTLM relay keep a session",
                "under a signing key the attacker controls, which defeats enforced SMB signing: an attacker",
                "who intercepts or coerces a privileged user's authentication can act on these hosts as",
                "that user. Only the server behaviour was tested, not a complete relay attack.",
                "",
                "According to the researcher (Blackfield) Microsoft fixed this in the September 2026 security",
                "updates under CVE-2026-69676 (published by Microsoft as 'Windows Kerberos Remote Code",
                "Execution Vulnerability', CVSS 8.8). https://blackfield.ch/blog/defeating-enforced-smb-signing/",
                "",
                "Recommendation: install the September 2026 cumulative update or later and test again; the fix",
                "is enabled through a feature flag, so a patched build number alone does not guarantee it is active."],
                self.output_paths['findings'] / 'smb_signing_bypass_reauth.txt')
        elif results['not_vulnerable']:
            self.logger.success(f"[+] None of the {len(results['not_vulnerable'])} probed host(s) allow a "
                                "cross-user SMB re-authentication swap")

        inconclusive = sorted(set((ip, host, msg) for ip, host, msg in results['inconclusive']))
        if inconclusive:
            self.logger.warning(f"[!] reauth_swap inconclusive on {len(inconclusive)} host(s) - check manually")
            write_lines([f"{ip} - {host}: {msg}" for ip, host, msg in inconclusive],
                        self.output_paths['checks'] / 'smb_signing_bypass_inconclusive.txt')

    def _module_available(self) -> bool:
        try:
            result = subprocess.run(['netexec', 'smb', '-L'], capture_output=True, text=True,
                                    encoding='utf-8', errors='replace', timeout=60)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False
        return MODULE in (result.stdout or '') + (result.stderr or '')

    def _run(self, hosts: List[str]) -> str:
        with self.target_files.temporary_targets(hosts) as hosts_file:
            cmd = ['netexec', 'smb', str(hosts_file), '-d', self.domain, '-u', self.username]
            cmd += ['-H', self.hashes] if self.hashes and not self.password else ['-p', self.password]
            options = [f'PROBE_USER={self.probe_user}']
            options.append(f'PROBE_NTHASH={self.probe_hash}' if self.probe_hash and not self.probe_password
                           else f'PROBE_PASS={self.probe_password}')
            cmd += ['-M', MODULE, '-o'] + options
            self.logger.info(f"[*] Running netexec reauth_swap against {len(hosts)} SMB host(s)")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, encoding='utf-8',
                                        errors='replace', timeout=1800)
            except subprocess.TimeoutExpired:
                self.logger.error("[-] netexec reauth_swap timed out")
                return ""
            except FileNotFoundError:
                self.logger.error("[-] netexec not found on system")
                return ""
        return (result.stdout or '') + (result.stderr or '')
