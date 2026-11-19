"""Veeam Backup & Replication domain membership check.

Veeam advises against joining the backup server to the production domain
("Backup server should not be a part of the production domain" in its Security &
Compliance Analyzer): whoever controls the domain can then reach the backups,
and several Veeam RCE vulnerabilities (e.g. CVE-2025-23120) only affected
domain-joined backup servers.

Veeam services register SPNs as {Service}/{FQDN} and {Service}/{NetBIOSName}
(Veeam KB4393). The Veeam Backup Service (VeeamBackupSvc) runs on the Backup &
Replication server and registers its SPN at each start; services running as
LocalSystem register on the computer object, services running under a domain
account on that user object. Other Veeam SPNs (e.g. VeeamDeploySvc /
VeeamGuestHelperSvc on backed-up machines) only show that Veeam is in use.

A missing SPN does not prove there is no domain-joined backup server: SPN
registration can fail or be disabled.
"""

import socket
from pathlib import Path
from typing import Dict, List, Optional

from ...utils.logger import get_logger
from ...utils.ldap import LDAPConnection
from ...utils.output import write_lines

BACKUP_SERVER_SERVICE = 'veeambackupsvc'
# Veeam Data Mover (proxy, Windows repository, backup server) and Installer Service
# (managed servers). VeeamGuestHelperSvc alone marks a machine that is backed up.
INFRASTRUCTURE_SERVICES = {'veeamtransportsvc', 'veeamdeploysvc'}
VEEAM_BACKUP_SERVICE_PORT = 9392
UAC_ACCOUNTDISABLE = 0x2


def _as_list(value) -> List:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


class VeeamChecker:
    """Finds Veeam Backup & Replication servers joined to the audited domain."""

    def __init__(self, ldap_conn: LDAPConnection, output_paths: Dict[str, Path]):
        self.ldap = ldap_conn
        self.output_paths = output_paths
        self.logger = get_logger()
        self.base_dn = ldap_conn.config.base_dn

    @staticmethod
    def _backup_hosts(entry) -> List[str]:
        """Hostnames to probe: the FQDN-style hosts in the VeeamBackupSvc SPNs, else the object name."""
        hosts = []
        for spn in entry['spns']:
            service, _, rest = spn.partition('/')
            host = rest.split(':')[0].split('/')[0]
            if service.lower() == BACKUP_SERVER_SERVICE and '.' in host and host.lower() not in hosts:
                hosts.append(host.lower())
        if not hosts and entry['type'] == 'computer' and '.' in entry['name']:
            hosts.append(entry['name'].lower())
        return hosts

    @staticmethod
    def _probe(host: str) -> Optional[bool]:
        """True if TCP 9392 is open, False if closed/filtered, None if the name doesn't resolve."""
        try:
            addr = socket.getaddrinfo(host, VEEAM_BACKUP_SERVICE_PORT, socket.AF_INET, socket.SOCK_STREAM)[0][4]
        except (socket.gaierror, IndexError, OSError):
            return None
        try:
            with socket.create_connection(addr, timeout=3):
                return True
        except OSError:
            return False

    def _confirm(self, entry):
        """Annotate a backup server entry with the result of the port 9392 probe."""
        results = []
        for host in self._backup_hosts(entry):
            state = self._probe(host)
            if state is True:
                results.append(f"confirmed: {host} TCP {VEEAM_BACKUP_SERVICE_PORT} open (Veeam Backup Service)")
            elif state is False:
                results.append(f"not confirmed: {host} TCP {VEEAM_BACKUP_SERVICE_PORT} closed or filtered")
            else:
                results.append(f"not confirmed: {host} could not be resolved")
        entry['confirmed'] = any(r.startswith('confirmed') for r in results)
        entry['probe'] = results or ["not confirmed: no hostname to test"]

    def check_veeam(self):
        self.logger.info("---Checking for domain-joined Veeam Backup & Replication servers---")
        try:
            objects = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(servicePrincipalName=Veeam*)',
                attributes=['sAMAccountName', 'dNSHostName', 'objectClass', 'userAccountControl',
                            'servicePrincipalName'],
            )
        except Exception as e:
            self.logger.error(f"[-] Error checking for Veeam SPNs: {e}")
            return

        servers, accounts, disabled, infrastructure, other = [], [], [], [], []
        for obj in objects:
            spns = [s for s in _as_list(obj.get('servicePrincipalName')) if str(s).lower().startswith('veeam')]
            if not spns:
                continue
            classes = [str(c).lower() for c in _as_list(obj.get('objectClass'))]
            is_computer = 'computer' in classes
            try:
                is_disabled = bool(int(obj.get('userAccountControl') or 0) & UAC_ACCOUNTDISABLE)
            except (TypeError, ValueError):
                is_disabled = False
            name = obj.get('dNSHostName') or obj.get('sAMAccountName') or '?'
            if isinstance(name, list):
                name = name[0]
            entry = {
                'name': str(name),
                'type': 'computer' if is_computer else 'user',
                'spns': sorted(spns),
            }
            services = {s.split('/')[0].lower() for s in spns}
            if BACKUP_SERVER_SERVICE in services:
                if is_disabled:
                    disabled.append(entry)
                elif is_computer:
                    servers.append(entry)
                else:
                    accounts.append(entry)
            elif services & INFRASTRUCTURE_SERVICES and is_computer and not is_disabled:
                infrastructure.append(entry)
            else:
                other.append(entry)

        def fmt(entries):
            lines = []
            for e in entries:
                lines.append(f"  - {e['name']} ({e['type']})")
                lines.extend(f"      {s}" for s in e['spns'])
                lines.extend(f"      [{p}]" for p in e.get('probe', []))
            return lines

        for entry in servers + accounts:
            self._confirm(entry)

        # A proxy/repository host with TCP 9392 open is the backup server itself whose
        # VeeamBackupSvc SPN was not registered.
        for entry in list(infrastructure):
            self._confirm(entry)
            if entry['confirmed']:
                entry['probe'].append("no VeeamBackupSvc SPN; identified as backup server by the open port")
                infrastructure.remove(entry)
                servers.append(entry)
            else:
                entry['probe'] = [r.replace('not confirmed: ', 'backup server port check: ') for r in entry['probe']]

        if servers or accounts:
            names = [f"{e['name']} ({'confirmed, port 9392 open' if e['confirmed'] else 'not confirmed'})"
                     for e in servers + accounts]
            self.logger.finding(f"Veeam Backup & Replication server joined to the domain: {', '.join(names)}")
            lines = ["Veeam Backup & Replication server found in the domain (VeeamBackupSvc SPN or TCP 9392):"]
            if servers:
                lines += ["", "Backup server computer object(s):"] + fmt(servers)
            if accounts:
                lines += ["", "Domain account(s) running the Veeam Backup Service (backup server is domain-joined;",
                          "also check these accounts for Kerberoasting and excessive privileges):"] + fmt(accounts)
            lines += [
                "",
                "Veeam advises not to join the backup server to the production domain. Anyone who",
                "compromises the domain (e.g. a Domain Admin) can log on to the backup server and",
                "delete or encrypt the backups, removing the ability to recover from ransomware.",
                "",
                f"Confirmation: TCP {VEEAM_BACKUP_SERVICE_PORT} (Veeam Backup Service) was tested from the audit host.",
                "'not confirmed' usually means a firewall blocks the port from this network; the",
                "SPN on an enabled object still shows a domain-joined backup server. An SPN can",
                "remain after Veeam was removed, so verify unconfirmed hosts manually.",
                "",
                "Recommendation: move the backup server to a workgroup or a separate management",
                "forest, use local accounts with MFA for the Veeam console, and keep immutable or",
                "offline copies of the backups.",
            ]
            write_lines(lines, self.output_paths['findings'] / 'Veeam_domain_joined.txt')

        if disabled:
            self.logger.warning(f"[!] Disabled object(s) with a Veeam Backup Service SPN: "
                                f"{', '.join(e['name'] for e in disabled)} (verify whether still in use)")
            write_lines(["Disabled objects with a VeeamBackupSvc SPN (likely decommissioned; verify):"] +
                        fmt(disabled),
                        self.output_paths['checks'] / 'Veeam_disabled_backup_server_objects.txt')

        if infrastructure:
            self.logger.warning(f"[!] Domain-joined Veeam infrastructure (proxy or repository): "
                                f"{', '.join(e['name'] for e in infrastructure)} - verify whether it stores backups")
            write_lines([
                "Domain-joined Veeam infrastructure servers (VeeamTransportSvc = Data Mover, used by",
                "backup proxies and Windows repositories; VeeamDeploySvc = Installer Service on",
                "managed servers):"] + fmt(infrastructure) + [
                "",
                "SPNs do not show whether a host is a proxy or a repository. If it is a backup",
                "repository, the backups are stored on a domain-joined server: anyone who compromises",
                "the domain can delete or encrypt them, even when the backup server itself is not",
                "domain-joined. A proxy only moves data and is lower risk.",
                "",
                "Verify the role in the Veeam console (Backup Infrastructure > Backup Repositories)",
                "or with the administrator. Recommendation: keep repositories outside the production",
                "domain (workgroup, management forest or a hardened Linux repository) and keep",
                "immutable or offline copies of the backups.",
            ], self.output_paths['checks'] / 'Veeam_domain_joined_infrastructure.txt')

        if other:
            self.logger.info(f"[*] {len(other)} object(s) with other Veeam SPNs (e.g. backed-up machines; saved to data)")
            write_lines(["Objects with other Veeam SPNs (VeeamGuestHelperSvc = machine backed up with",
                         "application-aware processing). Informational: shows Veeam is in use.", ""] + fmt(other),
                        self.output_paths['data'] / 'veeam_spns.txt')

        if not servers and not accounts:
            if infrastructure or other:
                self.logger.info("[*] Veeam is in use, but no Veeam Backup & Replication server was found in this "
                                 "domain (recommended: workgroup or management domain); verify where it runs")
            else:
                self.logger.success("[+] No Veeam SPNs found in the domain (note that SPN registration can fail "
                                    "or be disabled)")
