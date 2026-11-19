"""Access checks using netexec for SMB, RDP, WINRM, and MSSQL."""

import configparser
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Tuple, Optional

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.targets import TargetFiles, TargetScope
from ...utils.output import write_lines


class AccessChecker:
    """Check for local admin/access on various protocols using netexec."""
    
    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path],
                 domain: str = None, username: str = None, password: str = None,
                 hashes: str = None, target_files: TargetFiles = None):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.domain = domain
        self.username = username
        self.password = password
        self.hashes = hashes
        self.target_files = target_files or TargetFiles(output_paths['data'], TargetScope(), self.logger)
        self.pwn3d_label = self._get_pwn3d_label()
    
    def _get_pwn3d_label(self) -> str:
        """Read the pwn3d label the same way NetExec does.

        NetExec (nxc/paths.py, nxc/config.py) reads $NXC_PATH/nxc.conf, or
        ~/.nxc/nxc.conf when NXC_PATH isn't set, and uses
        config.get("nxc", "pwn3d_label", fallback="Pwn3d!").
        """
        default_label = "Pwn3d!"
        nxc_path = os.environ.get("NXC_PATH")
        config_path = Path(os.path.normpath(nxc_path)) if nxc_path else Path.home() / ".nxc"
        config_path = config_path / "nxc.conf"

        if not config_path.exists():
            self.logger.debug(f"nxc config not found at {config_path}, using default pwn3d_label: {default_label}")
            return default_label

        try:
            config = configparser.ConfigParser()
            config.read(config_path)
            label = config.get("nxc", "pwn3d_label", fallback=default_label)
            self.logger.debug(f"Using pwn3d_label from {config_path}: {label!r}")
            return label
        except Exception as e:
            self.logger.debug(f"Error reading nxc config {config_path}: {e}")
            return default_label
    
    def check_access(self):
        """Run all access checks."""
        self.logger.debug(f"[*] Using pwn3d_label: {self.pwn3d_label}")
        
        self._check_smb_access()
        self._check_winrm_access()
        self._check_rdp_access()
        self._check_mssql_access()
    
    def _get_hosts_file(self, filename: str, label: str) -> Optional[Path]:
        """Get the path to a hosts file if it exists."""
        hosts_file = self.output_paths['data'] / filename
        if self.target_files.read_discovered(hosts_file, label).targets:
            return hosts_file
        return None
    
    def _read_filtered_hosts(self, hosts_file: Path) -> Tuple[List[str], int]:
        result = self.target_files.read(hosts_file)
        return result.targets, result.excluded_count

    def _build_netexec_cmd(self, protocol: str, hosts_file: Path) -> List[str]:
        """Build netexec command with authentication."""
        cmd = ['netexec', protocol, str(hosts_file)]
        
        if self.domain:
            cmd.extend(['-d', self.domain])
        
        cmd.extend(['-u', self.username])
        
        if self.hashes and not self.password:
            cmd.extend(['-H', self.hashes])
        else:
            cmd.extend(['-p', self.password])
        
        return cmd
    
    def _run_netexec(self, protocol: str, hosts_file: Path, timeout: int = 300) -> str:
        """Run netexec and return output."""
        with self.target_files.approved_file(hosts_file, protocol.upper()) as target_file:
            if not target_file:
                return ""

            cmd = self._build_netexec_cmd(protocol, target_file)
            self.logger.debug(f"Running: {' '.join(cmd)}")

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    encoding='utf-8',
                    errors='replace',
                    timeout=timeout
                )
                output = (result.stdout or '') + (result.stderr or '')
            
                # Strip ANSI color codes
                output = re.sub(r'\x1b\[[0-9;]*m', '', output)
            
                return output
            except subprocess.TimeoutExpired:
                self.logger.error(f"[-] netexec {protocol} timed out")
                return ""
            except FileNotFoundError:
                self.logger.error("[-] netexec not found on system")
                return ""
            except Exception as e:
                self.logger.error(f"[-] Error running netexec {protocol}: {e}")
                return ""
    
    def _parse_pwn3d_output(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec output for lines containing pwn3d_label.
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        # NetExec prints the label as "(<label>)" after the credentials on [+]
        # lines (mark_pwned in nxc/connection.py). Matching that exact form on
        # success lines avoids false hits when the label is short or empty, or
        # appears in a hostname/username.
        marker = f"({self.pwn3d_label})"

        for line in re.sub(r'\x1b\[[0-9;]*m', '', output).split('\n'):
            if '[+]' in line and line.rstrip().endswith(marker):
                # Extract IP and hostname from line
                # Example: RDP  10.6.10.11  3389  WINTERFELL  [+] ... (Pwn3d!)
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                # Try to extract hostname - typically after port number
                # Format: PROTOCOL  IP  PORT  HOSTNAME  [status]
                parts = line.split()
                hostname = ""
                
                if ip_match:
                    ip = ip_match.group(1)
                    # Find hostname - it's typically the 4th field
                    # Look for uppercase word after port that doesn't start with [
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            # Next part is port, part after that should be hostname
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    results.append((ip, hostname))
        
        return results
    
    def _parse_mssql_success(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec MSSQL output for [+] success lines.
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        
        for line in output.split('\n'):
            # For MSSQL, [+] indicates successful access (no pwn3d required)
            if '[+]' in line:
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    hostname = ""
                    
                    # Extract hostname
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    # Avoid duplicates
                    if (ip, hostname) not in results:
                        results.append((ip, hostname))
        
        return results
    
    def _format_results(self, results: List[Tuple[str, str]]) -> List[str]:
        """Format results as 'IP - Computername' lines."""
        lines = []
        seen = set()
        
        for ip, hostname in results:
            key = (ip, hostname)
            if key not in seen:
                seen.add(key)
                if hostname:
                    lines.append(f"{ip} - {hostname}")
                else:
                    lines.append(ip)
        
        return sorted(lines)
    
    def _count_hosts_in_file(self, hosts_file: Path) -> int:
        """Count number of non-empty lines in hosts file."""
        try:
            return self.target_files.count(hosts_file)
        except Exception:
            return 0
    
    def _check_smb_access(self):
        """Check for local admin access over SMB."""
        self.logger.info("---Checking for local admin access over SMB---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_smb.txt', 'SMB')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec SMB against {host_count} host(s)")
        
        output = self._run_netexec('smb', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec SMB output:\n{output}")
        
        results = self._parse_pwn3d_output(output)
        
        if results:
            formatted = self._format_results(results)
            self.logger.finding(f"There are {len(formatted)} systems where the current user has local admin over SMB")
            write_lines(formatted, self.output_paths['findings'] / 'access_localadmin_smb.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has local admin over SMB")
    
    def _check_winrm_access(self):
        """Check for access over WINRM."""
        self.logger.info("---Checking for access over WINRM---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_winrm.txt', 'WinRM')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec WINRM against {host_count} host(s)")
        
        output = self._run_netexec('winrm', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec WINRM output:\n{output}")
        
        results = self._parse_pwn3d_output(output)
        
        if results:
            formatted = self._format_results(results)
            self.logger.finding(f"There are {len(formatted)} systems where the current user has access over WINRM")
            write_lines(formatted, self.output_paths['findings'] / 'access_winrm.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has access over WINRM")
    
    def _netexec_confirms_rdp_logon(self) -> Optional[bool]:
        """Whether the installed NetExec only marks RDP pwn3d after a real logon.

        NetExec releases up to at least v1.5.1 mark every successful RDP
        connection as pwn3d, which only proves the credentials are valid.
        Since Nov 2026 (main, PR #1486) NetExec waits for the Save Session Info
        PDU via rdp.login_and_confirm(). Detect that by importing NetExec with
        its own interpreter (from the netexec launcher's shebang).
        Returns True/False, or None if it can't be determined.
        """
        if hasattr(self, '_rdp_confirm_cache'):
            return self._rdp_confirm_cache
        result = None
        try:
            launcher = shutil.which('netexec') or shutil.which('nxc')
            if launcher:
                with open(launcher, 'rb') as f:
                    first = f.readline().decode(errors='ignore').strip()
                if first.startswith('#!') and 'python' in first:
                    python = first[2:].strip().split()[0]
                    # nxc/protocols has both an rdp/ package and rdp.py (NetExec loads
                    # the module by path), so locate the package and read rdp.py.
                    probe = subprocess.run(
                        [python, '-c', 'import nxc, os; print(os.path.dirname(nxc.__file__))'],
                        capture_output=True, text=True, timeout=30
                    )
                    rdp_py = Path(probe.stdout.strip().splitlines()[-1]) / 'protocols' / 'rdp.py' \
                        if probe.returncode == 0 and probe.stdout.strip() else None
                    if rdp_py and rdp_py.is_file():
                        result = 'def login_and_confirm' in rdp_py.read_text(errors='ignore') \
                            or 'async def login_and_confirm' in rdp_py.read_text(errors='ignore')
        except Exception as e:
            self.logger.debug(f"Could not determine NetExec RDP logon confirmation support: {e}")
        self._rdp_confirm_cache = result
        return result
    
    def _check_rdp_access(self):
        """Check where the current user can log on over RDP.

        The RDP pwn3d label is only a reliable "can log on" signal with a NetExec
        that confirms the interactive logon (see _netexec_confirms_rdp_logon) and
        on hosts with NLA enabled. Older NetExec marks any valid credentials as
        pwn3d, and with NLA off the connection completes before Windows checks
        the logon. Those results are reported for manual verification.
        It never means local admin.
        """
        self.logger.info("---Checking for RDP logon access---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_rdp.txt', 'RDP')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec RDP against {host_count} host(s)")
        
        output = self._run_netexec('rdp', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec RDP output:\n{output}")
        
        results = self._parse_pwn3d_output(output)
        nla_off_ips = {ip for ip, _ in self._parse_nla_disabled(output)}
        confirms = self._netexec_confirms_rdp_logon()
        
        confirmed, unverified = [], []
        for ip, hostname in results:
            if confirms is not True:
                reason = ("installed NetExec marks any valid credentials as pwn3d on RDP" if confirms is False
                          else "could not determine whether the installed NetExec confirms the RDP logon")
                unverified.append((ip, hostname, reason))
            elif ip in nla_off_ips:
                unverified.append((ip, hostname, "NLA disabled - the logon itself isn't verified"))
            else:
                confirmed.append((ip, hostname))
        
        if confirmed:
            formatted = self._format_results(confirmed)
            self.logger.finding(f"There are {len(formatted)} systems where the current user can log on over RDP")
            write_lines(formatted, self.output_paths['findings'] / 'access_rdp.txt')
        elif not unverified:
            self.logger.success("[+] There are no systems where the current user can log on over RDP")
        
        if unverified:
            self.logger.warning(
                f"[!] RDP accepted the credentials on {len(unverified)} systems, but whether the user can actually "
                "log on couldn't be confirmed - verify manually (e.g. xfreerdp)"
            )
            write_lines([f"{ip} ({hostname}): {reason}" for ip, hostname, reason in unverified],
                        self.output_paths['checks'] / 'access_rdp_verify.txt')
        
        # Check for NLA disabled
        self.logger.info("---Checking for RDP NLA configuration---")
        nla_disabled = self._parse_nla_disabled(output)
        
        if nla_disabled:
            formatted = self._format_results(nla_disabled)
            self.logger.finding(f"There are {len(formatted)} systems with RDP NLA disabled")
            write_lines(formatted, self.output_paths['findings'] / 'rdp_nla_disabled.txt')
        else:
            self.logger.success("[+] All RDP systems have NLA enabled")
    
    def _parse_nla_disabled(self, output: str) -> List[Tuple[str, str]]:
        """Parse netexec RDP output for hosts with NLA disabled (nla:False).
        
        Returns list of (IP, Computername) tuples.
        """
        results = []
        
        for line in output.split('\n'):
            # Look for nla:False in the output
            # Format: RDP  IP  PORT  HOSTNAME  [*] ... (nla:False)
            if 'nla:False' in line or 'nla:false' in line.lower():
                ip_match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', line)
                
                if ip_match:
                    ip = ip_match.group(1)
                    hostname = ""
                    
                    # Extract hostname
                    parts = line.split()
                    for i, part in enumerate(parts):
                        if part == ip and i + 2 < len(parts):
                            potential_hostname = parts[i + 2]
                            if not potential_hostname.startswith('['):
                                hostname = potential_hostname
                                break
                    
                    # Avoid duplicates
                    if (ip, hostname) not in results:
                        results.append((ip, hostname))
        
        return results

    def _check_mssql_access(self):
        """Check for access over MSSQL and sysadmin privileges."""
        self.logger.info("---Checking for access over MSSQL---")
        
        hosts_file = self._get_hosts_file('scandata_hostalive_mssql.txt', 'MSSQL')
        if not hosts_file:
            return
        
        # Count hosts
        host_count = self._count_hosts_in_file(hosts_file)
        self.logger.info(f"[*] Running netexec MSSQL against {host_count} host(s)")
        
        output = self._run_netexec('mssql', hosts_file)
        if not output:
            return
        
        # Debug: show raw output
        self.logger.debug(f"Raw netexec MSSQL output:\n{output}")
        
        # For MSSQL, [+] means access (no pwn3d required)
        access_results = self._parse_mssql_success(output)
        
        if access_results:
            formatted = self._format_results(access_results)
            self.logger.finding(f"There are {len(formatted)} systems where the current user has access over MSSQL")
            write_lines(formatted, self.output_paths['findings'] / 'access_mssql.txt')
        else:
            self.logger.success("[+] There are no systems where the current user has access over MSSQL")
        
        # Check for sysadmin (pwn3d_label means sysadmin on MSSQL)
        self.logger.info("---Checking for sysadmin access over MSSQL---")
        sysadmin_results = self._parse_pwn3d_output(output)
        
        if sysadmin_results:
            formatted = self._format_results(sysadmin_results)
            self.logger.finding(f"There are {len(formatted)} systems where the current user is sysadmin on MSSQL")
            write_lines(formatted, self.output_paths['findings'] / 'access_mssql_sysadmin.txt')
        else:
            self.logger.success("[+] There are no systems where the current user is sysadmin on MSSQL")
