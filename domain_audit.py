"""Domain Audit Tool - Main entry point."""

import sys
from pathlib import Path
from typing import Optional

import typer
from typing_extensions import Annotated

from .config import Config, DOMAIN_FUNCTIONAL_LEVELS, ADMIN_THRESHOLD_PERCENTAGE
from .core.auth import Credentials, ADAuthManager, parse_hash
from .core.exceptions import DomainAuditError
from .utils.logger import get_logger, set_verbose
from .utils.output import create_output_directory, write_lines
from .utils.ldap import LDAPConnection, LDAPConfig
from .utils.dns import check_and_set_dns, reset_dns, is_admin, check_netexec_available
from .modules.enumeration import ADEnumerator
from .modules.checks import SecurityChecker

app = typer.Typer(
    name="domain-audit",
    help="Active Directory Domain Audit Tool",
    add_completion=False
)


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


@app.command()
def run(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain name (e.g., contoso.com)")],
    server: Annotated[str, typer.Option("--server", "-dc", help="Domain controller IP/hostname")],
    username: Annotated[str, typer.Option("--username", "-u", help="Username for authentication")],
    password: Annotated[Optional[str], typer.Option("--password", "-p", help="Password for authentication")] = None,
    hash: Annotated[Optional[str], typer.Option("--hash", "-H", help="NTLM hash (LM:NT or NT)")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o", help="Output directory")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Verbose output")] = False,
    skip_bloodhound: Annotated[bool, typer.Option("--skip-bloodhound", help="Skip BloodHound enumeration")] = False,
    bloodhound_options: Annotated[str, typer.Option("--bloodhound-options", help="BloodHound collection method: all, default, sessions, acl, computer")] = "all",
    skip_roasting: Annotated[bool, typer.Option("--skip-roasting", help="Skip Kerberoast/AS-REP roast")] = False,
    use_ldaps: Annotated[bool, typer.Option("--ldaps", help="Use LDAPS instead of LDAP")] = False,
    use_kerberos: Annotated[bool, typer.Option("--kerberos", "-k", help="Use Kerberos authentication")] = False,
):
    """
    Run comprehensive Active Directory domain audit.
    
    Examples:
        domain-audit -d contoso.com -dc 10.0.0.1 -u admin -p 'Password123!'
        domain-audit -d contoso.com -dc dc1.contoso.com -u admin -H aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0
    """
    # Setup logging
    set_verbose(verbose)
    logger = get_logger(verbose)
    
    # Check and set DNS to DC IP for proper hostname resolution
    logger.log_verbose("Checking DNS configuration")
    if not check_and_set_dns(server, domain, sys.argv):
        raise typer.Exit(1)
    
    # Check if netexec is available
    if not check_netexec_available():
        raise typer.Exit(1)
    
    # Validate credentials
    if not password and not hash:
        logger.error("[-] Please provide either --password or --hash")
        raise typer.Exit(1)
    
    # Parse hash if provided
    lm_hash, nt_hash = parse_hash(hash) if hash else (None, None)
    
    # Create credentials
    creds = Credentials(
        domain=domain,
        username=username,
        password=password or "",
        lm_hash=lm_hash,
        nt_hash=nt_hash,
        use_kerberos=use_kerberos,
        use_ldaps=use_ldaps
    )
    
    # Test authentication
    logger.log_verbose("Testing AD authentication")
    auth_manager = ADAuthManager(creds, server)
    
    auth_result = auth_manager.test_authentication()
    
    if not auth_result:
        # Check if DC was reachable by checking if any errors were logged
        # The auth_manager already logs specific errors
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
            
            # Run security checks (Phase 4 and 5)
            checker = SecurityChecker(
                ldap_conn, paths,
                domain=domain,
                username=username,
                password=password,
                hashes=lm_hash + ":" + nt_hash if lm_hash and nt_hash else None,
                bloodhound_options=bloodhound_options,
                skip_bloodhound=skip_bloodhound
            )
            checker.run_all_checks()
            
    except Exception as e:
        logger.error(f"Enumeration failed: {e}")
        # Reset DNS before exiting on error
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


@app.command()
def check(
    domain: Annotated[str, typer.Option("--domain", "-d", help="Domain name")],
    server: Annotated[str, typer.Option("--server", "-dc", help="Domain controller")],
    username: Annotated[str, typer.Option("--username", "-u", help="Username")],
    check_name: Annotated[str, typer.Argument(help="Name of specific check to run")],
    password: Annotated[Optional[str], typer.Option("--password", "-p")] = None,
    hash: Annotated[Optional[str], typer.Option("--hash", "-H")] = None,
    output: Annotated[Optional[Path], typer.Option("--output", "-o")] = None,
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
):
    """Run a specific security check."""
    set_verbose(verbose)
    logger = get_logger(verbose)
    
    # Check and set DNS to DC IP for proper hostname resolution
    logger.log_verbose("Checking DNS configuration")
    if not check_and_set_dns(server, domain, sys.argv):
        raise typer.Exit(1)
    
    logger.info(f"Running check: {check_name}")
    # TODO: Implement specific check execution
    

if __name__ == "__main__":
    app()
