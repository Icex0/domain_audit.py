"""Domain Audit Tool - Main entry point."""

import sys
from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from .config import Config, DOMAIN_FUNCTIONAL_LEVELS, ADMIN_THRESHOLD_PERCENTAGE
from .core.auth import Credentials, ADAuthManager
from .core.exceptions import DomainAuditError
from .utils.logger import get_logger, set_verbose
from .utils.output import create_output_directory, write_lines
from .utils.ldap import LDAPConnection, LDAPConfig
from .utils.dependencies import check_and_set_dns, reset_dns, is_admin, check_netexec_available, check_certipy_available
from .modules.enumeration import ADEnumerator
from .modules.checks import SecurityChecker

app = typer.Typer(
    name="domain-audit",
    help="Active Directory Domain Audit Tool",
    add_completion=False,
    context_settings={"help_option_names": ["-h", "--help"]}
)


@app.callback(invoke_without_command=True)
def main(
    domain: Annotated[Optional[str], typer.Option("--domain", "-d", help="Domain name (e.g., contoso.com)")] = None,
    server: Annotated[Optional[str], typer.Option("--server", "-dc", help="Domain controller IP/hostname")] = None,
    username: Annotated[Optional[str], typer.Option("--username", "-u", help="Username for authentication")] = None,
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Password for authentication")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
    skip_bloodhound: Annotated[bool, typer.Option("--skip-bloodhound", help="Skip BloodHound enumeration")] = False,
    bloodhound_options: Annotated[str, typer.Option("--bloodhound-options", help="BloodHound collection method: all, default, sessions, acl, computer")] = "all",
    skip_roasting: Annotated[bool, typer.Option("--skip-roasting", help="Skip Kerberoast/AS-REP roast")] = False,
    use_ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS instead of LDAP")] = False,
    use_kerberos: Annotated[bool, typer.Option("--kerberos", "-k", help="Use Kerberos authentication")] = False,
    check: Annotated[Optional[str], typer.Option("--check", "-c", help="Run a specific check instead of full audit")] = None,
    list_checks: Annotated[bool, typer.Option("--list", "-L", help="List available checks")] = False,
):
    """
    Active Directory Domain Audit Tool.
    
    Run a comprehensive audit:
        domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'
    
    List available checks:
        domain-audit -L
    
    Run a specific check:
        domain-audit --check access -d contoso.com -dc 10.0.0.1 -u admin -p 'Pass!'
    """
    set_verbose(verbose)
    logger = get_logger(verbose)
    
    # List available checks
    if list_checks:
        logger.info("Available checks:")
        for name, description in SecurityChecker.list_checks().items():
            logger.info(f"  {name:20} - {description}")
        raise typer.Exit(0)
    
    # No options provided - show help
    if not domain and not server and not username and not check:
        print("Usage: domain-audit [OPTIONS]")
        print("\nRun 'domain-audit --help' for more information.")
        raise typer.Exit(0)
    
    # Run specific check or full audit
    if check:
        _run_check(
            check_name=check, domain=domain, server=server, username=username,
            password=password, output=output, verbose=verbose,
            use_ldaps=use_ldaps, bloodhound_options=bloodhound_options
        )
    else:
        _run_audit(
            domain=domain, server=server, username=username,
            password=password, output=output, verbose=verbose,
            skip_bloodhound=skip_bloodhound, bloodhound_options=bloodhound_options,
            skip_roasting=skip_roasting, use_ldaps=use_ldaps, use_kerberos=use_kerberos
        )


def _run_check(
    check_name: str, domain: str, server: str, username: str,
    password: Optional[str] = None,
    output: Optional[Path] = None, verbose: bool = False,
    use_ldaps: bool = False, bloodhound_options: str = "all"
):
    """Internal function to run a specific check."""
    logger = get_logger(verbose)
    
    # Validate required options
    if not domain:
        logger.error("[-] Missing required option: --domain / -d")
        raise typer.Exit(1)
    if not server:
        logger.error("[-] Missing required option: --server / -dc")
        raise typer.Exit(1)
    if not username:
        logger.error("[-] Missing required option: --username / -u")
        raise typer.Exit(1)
    if not password:
        logger.error("[-] Missing required option: --password / -p")
        raise typer.Exit(1)
    
    # Validate check name
    available = SecurityChecker.list_checks()
    if check_name not in available:
        logger.error(f"[-] Unknown check: {check_name}")
        logger.info("Use -L to list available checks")
        raise typer.Exit(1)
    
    # Check and set DNS
    logger.log_verbose("Checking DNS configuration")
    if not check_and_set_dns(server, domain, sys.argv):
        raise typer.Exit(1)
    
    # Create output directory
    paths = create_output_directory(domain, output)
    
    # Setup LDAP connection
    ldap_config = LDAPConfig(
        server=server,
        domain=domain,
        username=username,
        password=password or "",
        use_ldaps=use_ldaps
    )
    
    try:
        with LDAPConnection(ldap_config) as ldap_conn:
            checker = SecurityChecker(
                ldap_conn, paths,
                domain=domain,
                username=username,
                password=password,
                bloodhound_options=bloodhound_options
            )
            checker.run_check(check_name, bloodhound_options=bloodhound_options)
            
    except Exception as e:
        logger.error(f"Check failed: {e}")
        if is_admin():
            reset_dns()
        raise typer.Exit(1)
    
    # Reset DNS after completion
    if is_admin():
        logger.log_verbose("Resetting DNS configuration")
        reset_dns()
    
    logger.success(f"\n[+] Check '{check_name}' completed")


def _run_audit(
    domain: str, server: str, username: str,
    password: Optional[str] = None,
    output: Optional[Path] = None, verbose: bool = False,
    skip_bloodhound: bool = False, bloodhound_options: str = "all",
    skip_roasting: bool = False, use_ldaps: bool = False, use_kerberos: bool = False
):
    """Internal function to run the audit."""
    set_verbose(verbose)
    logger = get_logger(verbose)
    
    # Validate required options
    if not domain:
        logger.error("[-] Missing required option: --domain / -d")
        raise typer.Exit(1)
    if not server:
        logger.error("[-] Missing required option: --server / -dc")
        raise typer.Exit(1)
    if not username:
        logger.error("[-] Missing required option: --username / -u")
        raise typer.Exit(1)
    if not password:
        logger.error("[-] Missing required option: --password / -p")
        raise typer.Exit(1)
    
    # Check and set DNS to DC IP for proper hostname resolution
    logger.log_verbose("Checking DNS configuration")
    if not check_and_set_dns(server, domain, sys.argv):
        raise typer.Exit(1)
    
    # Check if netexec is available
    if not check_netexec_available():
        raise typer.Exit(1)
    
    # Check if certipy is available
    if not check_certipy_available():
        raise typer.Exit(1)
    
    # Create credentials
    creds = Credentials(
        domain=domain,
        username=username,
        password=password or "",
        use_kerberos=use_kerberos,
        use_ldaps=use_ldaps
    )
    
    # Test authentication
    logger.log_verbose("Testing AD authentication")
    auth_manager = ADAuthManager(creds, server)
    
    auth_result = auth_manager.test_authentication()
    
    if not auth_result:
        auth_manager.close()
        raise typer.Exit(1)
    
    # Create output directory
    paths = create_output_directory(domain, output)
    
    # Print explanation
    print_explanation(paths["root"])
    
    logger.section("EXECUTING CHECKS")
    logger.info("Starting domain audit...")
    
    # Setup LDAP connection for enumeration
    ldap_config = LDAPConfig(
        server=server,
        domain=domain,
        username=username,
        password=password or "",
        use_ldaps=use_ldaps
    )
    
    try:
        with LDAPConnection(ldap_config) as ldap_conn:
            # Run enumeration
            enumerator = ADEnumerator(ldap_conn, paths)
            domain_data = enumerator.enumerate_all()
            
            # Print domain summary
            _print_domain_summary(domain_data, paths, domain)
            
            # Run security checks
            checker = SecurityChecker(
                ldap_conn, paths,
                domain=domain,
                username=username,
                password=password,
                bloodhound_options=bloodhound_options,
                skip_bloodhound=skip_bloodhound
            )
            checker.run_all_checks()
            
    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        if is_admin():
            reset_dns()
        raise typer.Exit(1)
    
    auth_manager.close()
    
    # Reset DNS after completion if we have admin privileges
    if is_admin():
        logger.log_verbose("Resetting DNS configuration")
        success, msg = reset_dns()
        if success:
            logger.log_verbose(msg)
    
    logger.success("\n\n[+] Domain audit completed")


def print_explanation(output_dir: Path):
    """Print explanation of output structure."""
    logger = get_logger()
    
    logger.section("DATA EXPLAINED")
    logger.info(f"All data is written to {output_dir}")
    logger.info("In this folder are three subfolders")
    logger.info("files in \\findings\\ are findings that should be reported")
    logger.info("files in \\checks\\ needs to be checked")
    logger.info("files in \\data\\ is raw data")
    logger.info("")
    
    logger.section("COLORS EXPLAINED")
    logger.info("White is informational text")
    logger.success("Green means check has passed")
    logger.warning("Yellow means manually check the data")
    logger.error("Red means finding")
    logger.info("")


def _print_domain_summary(domain_data, paths, domain):
    """Print summary of domain enumeration."""
    logger = get_logger()
    
    logger.section("DOMAIN INFORMATION")
    
    user_count = len(domain_data.users)
    group_count = len(domain_data.groups)
    computer_count = len(domain_data.computers)
    dc_count = len(domain_data.domain_controllers)
    gpo_count = len(domain_data.gpos)
    ou_count = len(domain_data.ous)
    
    logger.info(f"Domain SID: {domain_data.domain_sid}")
    logger.info(f"In the domain {domain} there are:")
    logger.info(f"- {user_count} users")
    logger.info(f"- {group_count} groups")
    logger.info(f"- {computer_count} computers")
    logger.info(f"- {ou_count} OUs")
    logger.info(f"- {gpo_count} GPOs")
    logger.info(f"- {dc_count} Domain Controllers")
    
    # Save basic lists
    logger.section("BASIC ENUMERATION")
    
    # User lists
    if domain_data.users:
        users = [u.get('sAMAccountName', '') for u in domain_data.users if u.get('sAMAccountName')]
        write_lines(sorted(users), paths['data'] / 'list_users.txt')
        
        # Enabled users
        enabled_users = [
            u.get('sAMAccountName', '') for u in domain_data.users 
            if u.get('sAMAccountName') and not (u.get('userAccountControl', 0) & 2)
        ]
        write_lines(sorted(enabled_users), paths['data'] / 'list_users_enabled.txt')
    
    # Computer list
    if domain_data.computers:
        computers = [c.get('dNSHostName', '') for c in domain_data.computers if c.get('dNSHostName')]
        write_lines(sorted(computers), paths['data'] / 'list_computers.txt')
    
    # Group list
    if domain_data.groups:
        groups = [g.get('sAMAccountName', '') for g in domain_data.groups if g.get('sAMAccountName')]
        write_lines(sorted(groups), paths['data'] / 'list_groups.txt')
    
    logger.info("")


if __name__ == "__main__":
    app()
