"""Legacy access: computer account creation, Pre-Windows 2000 access/computers, ANONYMOUS LOGON."""

from typing import Dict
from ...utils.output import write_csv, write_lines
from ...utils.timeutil import to_datetime


class LegacyAccessMixin:
    """Mixin for OutdatedChecker (expects self.ldap, self.output_paths, self.logger, self.base_dn)."""

    def _check_domain_join(self):
        """Check whether normal users can add computer accounts to the domain.

        A normal user can create computer accounts when ms-DS-MachineAccountQuota
        is > 0 AND they hold "Add workstations to domain" (SeMachineAccountPrivilege)
        on the DCs - by default Authenticated Users via the Default Domain
        Controllers Policy. (Delegated create-computer rights on OUs are a separate
        path, not checked here.)
        """
        self.logger.info("---Checking domain join permissions---")
        
        try:
            from ...utils.user_rights import users_can_create_computers
            result = users_can_create_computers(self.ldap, self.logger, self.domain,
                                                self.username, self.password, self.hashes)
            quota = result.quota
            if quota <= 0:
                self.logger.success(f"[+] Users cannot join computers to domain (MachineAccountQuota = {quota})")
                return
            
            lines = [f"MachineAccountQuota: {quota}",
                     f"Add workstations to domain (SeMachineAccountPrivilege) on DCs - source: {', '.join(sorted(result.sources)) or 'unknown'}"]
            if result.possible:
                self.logger.finding(f"Normal users can add up to {quota} computer accounts to the domain "
                                    f"({'; '.join(p.split(' - ')[0] for p in result.principals)})")
                write_lines(lines + ["Non-admin principals holding the right:"] + [f"  {p}" for p in result.principals],
                            self.output_paths['findings'] / 'authenticated_users_can_join_domain.txt')
            elif result.possible is None:
                self.logger.warning(f"[!] MachineAccountQuota is {quota}; who holds 'Add workstations to domain' could not be determined - verify manually")
                write_lines(lines + result.errors, self.output_paths['checks'] / 'domain_join_verify.txt')
            else:
                self.logger.success(f"[+] MachineAccountQuota is {quota}, but only admins hold 'Add workstations to domain' on the DCs")
                write_lines(lines, self.output_paths['checks'] / 'domain_join.txt')
            
        except Exception as e:
            self.logger.error(f"[-] Error checking domain join permissions: {e}")

    def _check_prewindows2000_group(self):
        """Check Pre-Windows 2000 Compatible Access group."""
        self.logger.info("---Checking Pre-Windows 2000 Compatible Access---")
        
        try:
            # Find the group
            groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(cn=Pre-Windows 2000 Compatible Access)',
                attributes=['distinguishedName', 'member']
            )
            
            if not groups:
                self.logger.info("[*] Pre-Windows 2000 Compatible Access group not found")
                return
            
            group = groups[0]
            members = group.get('member', [])
            if isinstance(members, str):
                members = [members]
            
            write_csv([{'member': m} for m in members], self.output_paths['data'] / 'Pre-Windows_2000_Compatible_Access_Members.txt')
            
            # Check for Authenticated Users (S-1-5-11)
            authenticated_users = [m for m in members if 'S-1-5-11' in m or 'Authenticated Users' in m]
            
            if authenticated_users:
                self.logger.finding("Authenticated Users is member of Pre-Windows 2000 Compatible Access")
                write_csv([{'member': m} for m in authenticated_users], self.output_paths['findings'] / 'Pre-Windows_2000_Compatible_Access_Authenticated_users.txt')
            else:
                self.logger.success("[+] Authenticated Users NOT in Pre-Windows 2000 Compatible Access")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Pre-Windows 2000 group: {e}")

    def _check_anonymous_logon_groups(self):
        """Check if ANONYMOUS LOGON (S-1-5-7) is a member of any group."""
        self.logger.info("---Checking ANONYMOUS LOGON group memberships---")
        
        try:
            groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(objectClass=group)',
                attributes=['cn', 'distinguishedName', 'member']
            )
            
            if not groups:
                self.logger.info("[*] No groups found")
                return
            
            findings = []
            
            for group in groups:
                members = group.get('member') or []
                if isinstance(members, str):
                    members = [members]
                
                for member in members:
                    if 'S-1-5-7' in member or 'ANONYMOUS LOGON' in member.upper():
                        group_name = group.get('cn', group.get('distinguishedName', 'unknown'))
                        self.logger.finding(f"ANONYMOUS LOGON is member of '{group_name}'")
                        findings.append(f"{group_name}: ANONYMOUS LOGON (S-1-5-7)")
                        break
            
            if findings:
                write_lines(findings, self.output_paths['findings'] / 'anonymous_logon_group_membership.txt')
            else:
                self.logger.success("[+] ANONYMOUS LOGON is not a member of any group")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking ANONYMOUS LOGON group membership: {e}")

    def _check_prewindows2000_computers(self):
        """Find pre-created "pre-Windows 2000" computer accounts and their likely password.

        Pre-created computer accounts have userAccountControl exactly 4128
        (WORKSTATION_TRUST_ACCOUNT | PASSWD_NOTREQD) - the same filter NetExec's
        pre2k module uses. When created with "Assign this computer account as a
        pre-Windows 2000 computer", the password is the lowercase computer name
        without '$', truncated to 14 characters. After the first logon the
        password is normally changed, so accounts that never logged on are the
        likely hits.
        """
        self.logger.info("---Checking Pre-Windows 2000 computers---")
        
        try:
            computers = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=computer)(userAccountControl=4128))',
                attributes=['sAMAccountName', 'lastLogonTimestamp', 'pwdLastSet', 'badPwdCount', 'msDS-ResultantPSO']
            )
            
            if not computers:
                self.logger.success("[+] No pre-created (pre-Windows 2000) computer accounts found")
                return
            
            never_used, used = [], []
            by_name = {}
            for comp in computers:
                sam = comp.get('sAMAccountName', '')
                if not sam:
                    continue
                name = sam.rstrip('$')
                entry = (name, name.lower()[:14])
                by_name[name] = comp
                last_logon = comp.get('lastLogonTimestamp')
                if isinstance(last_logon, list):
                    last_logon = last_logon[0] if last_logon else None
                if to_datetime(last_logon) is not None:
                    used.append(entry)
                else:
                    never_used.append(entry)
            
            all_entries = never_used + used
            write_lines([n for n, _ in all_entries], self.output_paths['checks'] / 'list_computers_Pre-Windows2000Computers.txt')
            write_lines([p for _, p in all_entries], self.output_paths['checks'] / 'list_computers_Pre-Windows2000Computers_pass.txt')
            
            tested = self._test_prewindows2000_passwords(all_entries, by_name)
            valid = [(n, p) for n, p in all_entries if tested.get(n, (None,))[0] == 'valid']
            wrong = [n for n, _ in all_entries if tested.get(n, (None,))[0] == 'wrong']
            unclear = [(n, tested[n][1]) for n, _ in all_entries if tested.get(n, (None,))[0] == 'error']
            untested_never = [(n, p) for n, p in never_used if n not in tested]
            untested_used = [(n, p) for n, p in used if n not in tested]
            
            if valid:
                self.logger.finding(f"{len(valid)} pre-created computer accounts use their default password (lowercase computer name)")
                write_lines([f"{n}$:{p}" for n, p in valid],
                            self.output_paths['findings'] / 'Pre-Windows2000Computers_valid_password.txt')
            if wrong:
                self.logger.success(f"[+] {len(wrong)} pre-created computer accounts don't use the default password")
            if unclear:
                self.logger.warning(f"[!] {len(unclear)} pre-created computer accounts could not be tested - verify manually")
                write_lines([f"{n}$: {reason}" for n, reason in unclear],
                            self.output_paths['checks'] / 'Pre-Windows2000Computers_verify.txt')
            if untested_never:
                self.logger.finding(
                    f"{len(untested_never)} untested pre-created computer accounts never logged on - password is likely the "
                    "lowercase computer name (pre-Windows 2000)"
                )
                write_lines([f"{n}$:{p}" for n, p in untested_never],
                            self.output_paths['findings'] / 'Pre-Windows2000Computers_never_logged_on.txt')
            if untested_used:
                self.logger.warning(
                    f"[!] {len(untested_used)} untested pre-created computer accounts have logged on before - the default "
                    "password was probably changed, verify manually"
                )
            if untested_never or untested_used:
                self.logger.info("[*] Verify with: netexec ldap <dc> -u <user> -p <pass> -M pre2k "
                                 "(STATUS_NOLOGON_WORKSTATION_TRUST_ACCOUNT over SMB also means the password is valid)")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking Pre-Windows 2000 computers: {e}")

    def _test_prewindows2000_passwords(self, entries, by_name) -> Dict[str, tuple]:
        """Try one Kerberos TGT request per candidate with the default password.

        Same approach as NetExec's pre2k module, using impacket (already used for
        roasting). Safeguards: no testing when the domain lockout threshold is 1;
        accounts with a fine-grained password policy (unknown lockout) or whose
        badPwdCount on this DC is one attempt away from lockout are skipped.
        The request goes to the DC this tool reads LDAP from, because
        badPwdCount is tracked per DC. Side effects: a failed attempt adds one
        bad password count and a 4771 event; a success updates the account's
        last logon time.

        Returns {name: ('valid'|'wrong'|'error', reason)} for tested accounts.
        """
        results: Dict[str, tuple] = {}
        if not entries:
            return results
        try:
            from impacket.krb5 import constants
            from impacket.krb5.kerberosv5 import getKerberosTGT, KerberosError
            from impacket.krb5.types import Principal
        except ImportError:
            self.logger.warning("[!] impacket not available - pre-created computer passwords not tested")
            return results
        
        threshold = 0
        try:
            policy = self.ldap.query(self.base_dn, '(objectClass=domainDNS)', ['lockoutThreshold'])
            threshold = int(policy[0].get('lockoutThreshold') or 0) if policy else 0
        except Exception as e:
            self.logger.debug(f"Could not read lockoutThreshold: {e}")
        if threshold == 1:
            self.logger.warning("[!] Domain lockout threshold is 1 - not testing pre-created computer passwords")
            return results
        
        domain = self.ldap.config.domain
        kdc = self.ldap.config.server
        self.logger.info(f"[*] Testing {len(entries)} pre-created computer account(s) with one Kerberos logon attempt each")
        for name, password in entries:
            comp = by_name.get(name, {})
            if comp.get('msDS-ResultantPSO'):
                self.logger.debug(f"Skipping {name}$: fine-grained password policy applies (lockout threshold unknown)")
                continue
            bad = int(comp.get('badPwdCount') or 0)
            if threshold and bad >= threshold - 1:
                self.logger.debug(f"Skipping {name}$: badPwdCount {bad} is close to the lockout threshold {threshold}")
                continue
            principal = Principal(f"{name}$", type=constants.PrincipalNameType.NT_PRINCIPAL.value)
            try:
                getKerberosTGT(principal, password, domain, b'', b'', None, kdc)
                results[name] = ('valid', '')
            except KerberosError as e:
                code = e.getErrorCode()
                if code == constants.ErrorCodes.KDC_ERR_PREAUTH_FAILED.value:
                    results[name] = ('wrong', '')
                else:
                    results[name] = ('error', str(e))
            except Exception as e:
                results[name] = ('error', str(e))
        return results
