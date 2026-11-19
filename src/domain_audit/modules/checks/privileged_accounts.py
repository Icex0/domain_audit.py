"""Privileged account hardening: Protected Users, delegation flag, password age, KRBTGT."""

from datetime import datetime
from ...utils.output import write_csv, write_lines
from ...utils.timeutil import older_than
from ...utils.admins import AdminResolver


class PrivilegedAccountsMixin:
    """Mixin for OutdatedChecker (expects self.ldap, self.output_paths, self.logger, self.base_dn)."""

    def _check_privileged_objects(self):
        """Check privileged users for security settings."""
        self.logger.info("---Checking privileged objects security---")
        
        try:
            # Enabled users with adminCount=1. Disabled accounts can't authenticate, and
            # krbtgt / RODC krbtgt_<n> accounts (adminCount=1, always disabled) are
            # excluded explicitly: they can't be in Protected Users or be delegated.
            privileged = self.ldap.query(
                search_base=self.base_dn,
                search_filter=(
                    '(&(objectCategory=person)(objectClass=user)(adminCount=1)'
                    '(!(userAccountControl:1.2.840.113556.1.4.803:=2))'
                    '(!(sAMAccountName=krbtgt))(!(sAMAccountName=krbtgt_*)))'
                ),
                attributes=['sAMAccountName', 'distinguishedName', 'userAccountControl', 'pwdLastSet']
            )

            if not privileged:
                self.logger.info("[*] No enabled privileged users found")
                return

            # Check if privileged users are in Protected Users group (direct or nested)
            protected_dns = self._get_protected_users_dns()
            not_protected = [
                u for u in privileged
                if (u.get('distinguishedName') or '').lower() not in protected_dns
            ]

            if not_protected:
                self.logger.finding(f"{len(not_protected)} privileged users NOT in Protected Users group")
                names = [u.get('sAMAccountName', '') for u in not_protected if u.get('sAMAccountName')]
                write_lines(names, self.output_paths['findings'] / 'administrators_notin_protectedusersgroup.txt')
            else:
                self.logger.success("[+] All privileged users are in Protected Users group")
            
            # Check NOT_DELEGATED flag (0x100000 = 1048576). Protected Users members
            # can't be delegated anyway, so they don't need the flag.
            not_delegated = []
            for user in not_protected:
                uac = user.get('userAccountControl', 0)
                if isinstance(uac, str):
                    uac = int(uac)
                if not (uac & 1048576):
                    not_delegated.append(user)

            if not_delegated:
                self.logger.finding(f"{len(not_delegated)} privileged users can be delegated (no NOT_DELEGATED flag and not in Protected Users)")
                names = [u.get('sAMAccountName', '') for u in not_delegated if u.get('sAMAccountName')]
                write_lines(names, self.output_paths['findings'] / 'administrators_delegation_flag.txt')
            else:
                self.logger.success("[+] All privileged users are protected from delegation (NOT_DELEGATED flag or Protected Users)")
            
            # Check computers in high privileged groups
            high_priv_groups = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectClass=group)(adminCount=1)(!(cn=Cert Publishers)))',
                attributes=['distinguishedName', 'cn']
            )
            
            if high_priv_groups is not None and len(high_priv_groups) > 0:
                # Get DNs of high privileged groups
                high_priv_dns = [g['distinguishedName'] for g in high_priv_groups if g.get('distinguishedName')]
                
                # Query computers and check memberOf
                all_computers = self.ldap.query(
                    search_base=self.base_dn,
                    search_filter='(objectClass=computer)',
                    attributes=['sAMAccountName', 'memberOf']
                )
                
                computers_in_groups = []
                for comp in (all_computers or []):
                    member_of = comp.get('memberOf') or []
                    if isinstance(member_of, str):
                        member_of = [member_of]
                    if any(g in high_priv_dns for g in member_of):
                        computers_in_groups.append(comp)
                
                if computers_in_groups:
                    self.logger.finding(f"{len(computers_in_groups)} computers in high privileged groups")
                    write_csv(computers_in_groups, self.output_paths['findings'] / 'computers_part_of_highprivilegedgroups.txt')
                else:
                    self.logger.success("[+] No computers in high privileged groups")
            
        except Exception as e:
            self.logger.error(f"[-] Error checking privileged objects: {e}")

    def _get_protected_users_dns(self) -> set:
        """Lower-cased DNs of all direct and nested members of Protected Users (RID 525)."""
        try:
            admins = AdminResolver(self.ldap)
            sid = f'{admins.domain_sid}-525'
            if not admins.group_dn(sid):
                self.logger.info("[*] Protected Users group not found (requires Windows Server 2012 R2 domain functional level)")
                return set()
            return {m['distinguishedName'].lower() for m in admins.nested_members(sid, attributes=['distinguishedName'])
                    if m.get('distinguishedName')}
        except Exception as e:
            self.logger.error(f"[-] Error resolving Protected Users members: {e}")
            return set()

    def _check_privileged_old_passwords(self):
        """Check if privileged users have passwords older than 180 days."""
        self.logger.info("---Checking if privileged users have password older than 180 days---")
        
        try:
            privileged = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(&(objectCategory=person)(objectClass=user)(adminCount=1)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))',
                attributes=['sAMAccountName', 'pwdLastSet']
            )
            
            if not privileged:
                self.logger.info("[*] No privileged users found")
                return
            
            old_password_priv = []
            for user in privileged:
                pwd_last_set = user.get('pwdLastSet')
                if pwd_last_set and pwd_last_set != '0':
                    if self._is_pwd_old(pwd_last_set, 180):
                        old_password_priv.append(user)
            
            if old_password_priv:
                self.logger.finding(f"{len(old_password_priv)} privileged users with password older than 180 days")
                # Include pwdLastSet in output
                lines = []
                for u in old_password_priv:
                    name = u.get('sAMAccountName', 'unknown')
                    pwd = u.get('pwdLastSet')
                    if isinstance(pwd, datetime):
                        pwd_str = pwd.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        pwd_str = str(pwd) if pwd else 'unknown'
                    lines.append(f"{name} - pwdLastSet: {pwd_str}")
                write_lines(lines, self.output_paths['findings'] / 'oldpassword_privilegedusers.txt')
            else:
                self.logger.success("[+] No privileged users with password older than 180 days")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking privileged user passwords: {e}")

    def _check_krbtgt_password(self):
        """Check if KRBTGT account has password older than 180 days."""
        self.logger.info("---Checking if KRBTGT has password older than 180 days---")
        
        try:
            krbtgt = self.ldap.query(
                search_base=self.base_dn,
                search_filter='(sAMAccountName=krbtgt)',
                attributes=['sAMAccountName', 'pwdLastSet']
            )
            
            if krbtgt:
                krbtgt_pwd = krbtgt[0].get('pwdLastSet')
                if krbtgt_pwd and krbtgt_pwd != '0':
                    if self._is_pwd_old(krbtgt_pwd, 180):
                        self.logger.finding("KRBTGT account has password older than 180 days")
                        # Format the pwdLastSet date for output (remove microseconds and timezone)
                        if isinstance(krbtgt_pwd, datetime):
                            pwd_str = krbtgt_pwd.strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            pwd_str = str(krbtgt_pwd)
                        write_lines([f"pwdLastSet: {pwd_str}"], self.output_paths['findings'] / 'oldpassword_krbtgt.txt')
                    else:
                        self.logger.success("[+] KRBTGT password is not older than 180 days")
                else:
                    self.logger.info("[*] KRBTGT pwdLastSet not available")
            else:
                self.logger.info("[*] KRBTGT account not found")
                
        except Exception as e:
            self.logger.error(f"[-] Error checking KRBTGT password: {e}")

    @staticmethod
    def _is_pwd_old(pwd_last_set, days=180) -> bool:
        """True if the password was set more than `days` ago. pwdLastSet 0
        ("must change at next logon") means the real age is unknown and is
        reported as old too."""
        result = older_than(pwd_last_set, days)
        if result is None:
            return pwd_last_set not in (None, '', [])   # 0 / 1601 epoch
        return result
