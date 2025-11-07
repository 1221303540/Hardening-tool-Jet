#!/usr/bin/env python3
import pyodbc
import getpass
import platform
from typing import Dict, List, Any, Tuple, Optional
from utils import write_to_file, format_check_result
from constants import (
    SEPARATOR_LENGTH, SECTION_SEPARATOR_CHAR, SCORE_CRITICAL, SCORE_WARNING,
    AUDIT_LEVEL_NONE, AUDIT_LEVEL_SUCCESS, AUDIT_LEVEL_FAILED, AUDIT_LEVEL_BOTH,
    AUTH_MODE_MIXED, AUTH_MODE_WINDOWS_ONLY
)
from checkers.remediation_scripts import REMEDIATION_SQL

if platform.system() == "Windows": # Import winreg only if on Windows
    try:
        import winreg
    except ImportError:
        winreg = None
else:
    winreg = None

# HELPER FUNCTIONS FOR REMEDIATION
def _apply_sql_batch(cursor: Any, conn: Any, commands: List[str], utils: Any) -> None:
    for sql_command in commands:
        cursor.execute(sql_command)
    conn.commit()
    utils.write_to_file("    Fix applied successfully.")

def remediate_by_key(cursor: Any, conn: Any, key: str, utils: Any) -> bool:
    commands = REMEDIATION_SQL.get(key)
    if not commands:
        utils.write_to_file("   No automated remediation available for this finding.")
        return False
    try:
        _apply_sql_batch(cursor, conn, commands, utils)
        return True
    except Exception as e:
        utils.write_to_file(f"    ERROR applying fix: {e}")
        return False

def _extract_findings(report_log: List[str]) -> List[str]:
    return [line for line in report_log if line.strip().startswith(("[CRIT]", "[WARN]"))]

def run_interactive_remediation(config: Dict[str, Any], utils: Any) -> List[str]:
    write_to_file = utils.write_to_file
    print_separator = getattr(utils, 'print_separator', lambda c, n: None)

    write_to_file("[MODE] Running in INTERACTIVE REMEDIATION mode.")

    try:
        server = config.get('server', 'localhost')
        database = config.get('database', 'master')
        username = config.get('username', 'sa')
        password = config.get('password', None)
        if not password:
            password = getpass.getpass(f"Enter password for MS-SQL user '{username}': ")

        conn_string = (
            f"DRIVER={config.get('driver')};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={username};"
            f"PWD={password};"
            "TrustServerCertificate=yes;"
            "Encrypt=yes;"
        )

        write_to_file(f"\nConnecting to MS-SQL Server {server}...")
        conn = pyodbc.connect(conn_string)
        cursor = conn.cursor()
        write_to_file("Connected successfully.\n")

        write_to_file("Scanning...")
        report_log = run_all_checks({**config, 'password': password}, utils)
        checks_run = 12 # update if checks added/removed
        write_to_file(f"Scan complete. {checks_run} checks run.")

        findings = _extract_findings(report_log)
        # Deduplicate exact lines to avoid repeated prompts
        seen = set()
        unique_findings = []
        for f in findings:
            if f not in seen:
                seen.add(f)
                unique_findings.append(f)

        write_to_file(f"\nFound {len(unique_findings)} findings to remediate.")
        print_separator(SECTION_SEPARATOR_CHAR, SEPARATOR_LENGTH)
        write_to_file("### Interactive Remediation ###")
        print_separator(SECTION_SEPARATOR_CHAR, SEPARATOR_LENGTH)

        for finding in unique_findings:
            write_to_file("\n" + finding)

            # High-risk notice for auth mode change
            if "Server Authentication" in finding and "Mixed Mode" in finding:
                write_to_file("\n    *** HIGH RISK ACTION WARNING ***")
                write_to_file("    This fix will change the server to Windows-Only Authentication.")
                write_to_file("    All SQL logins (like 'sa') will STOP working.")
                write_to_file("    This action requires a server RESTART to apply.\n")

            choice = input("    Do you want to apply the fix for this finding? (y/n): ").lower()
            if choice not in ['y', 'yes']:
                write_to_file("    Skipping this finding.")
                write_to_file("------------------------------------------------------------")
                continue

            applied = False
            if "xp_cmdshell Status: ENABLED" in finding:
                write_to_file("    Applying fix for 'xp_cmdshell'...")
                applied = remediate_by_key(cursor, conn, "DISABLE_XP_CMDSHELL", utils)
            elif "CLR Integration" in finding and "ENABLED" in finding:
                write_to_file("    Applying fix for 'CLR Integration'...")
                applied = remediate_by_key(cursor, conn, "DISABLE_CLR", utils)
            elif "Ad Hoc Distributed Queries" in finding and "ENABLED" in finding:
                write_to_file("    Applying fix for 'Ad Hoc Distributed Queries'...")
                applied = remediate_by_key(cursor, conn, "DISABLE_AD_HOC_DISTRIBUTED", utils)
            elif "Database Mail XPs" in finding and "ENABLED" in finding:
                write_to_file("    Applying fix for 'Database Mail XPs'...")
                applied = remediate_by_key(cursor, conn, "DISABLE_DATABASE_MAIL_XPS", utils)
            elif "Ole Automation Procedures" in finding and "ENABLED" in finding:
                write_to_file("    Applying fix for 'Ole Automation Procedures'...")
                applied = remediate_by_key(cursor, conn, "DISABLE_OLE_AUTOMATION", utils)
            elif "'sa' Account Status" in finding and "ENABLED" in finding:
                write_to_file("    Applying fix for 'sa' account (disable)...")
                applied = remediate_by_key(cursor, conn, "DISABLE_SA_ACCOUNT", utils)
            elif "Server Authentication" in finding and "Mixed Mode" in finding:
                write_to_file("    Applying fix for 'Server Authentication' (set Windows Auth Mode)...")
                write_to_file("    ⚠️ This change requires a SQL Server service restart to take effect.")
                applied = remediate_by_key(cursor, conn, "ENABLE_WINDOWS_AUTH_MODE", utils)
            elif "Login Auditing" in finding and ("None" in finding or "Successful logins only" in finding or "Both failed and successful logins" in finding):
                write_to_file("    Applying fix for 'Login Auditing' (Failed logins only)...")
                write_to_file("    ⚠️ This change may require a SQL Server service restart to take effect.")
                applied = remediate_by_key(cursor, conn, "SET_AUDITLEVEL_FAILED_ONLY", utils)
            else:
                write_to_file("    No automated remediation available for this finding.")

            if applied:
                write_to_file("    Fix applied.")
            write_to_file("------------------------------------------------------------")

        write_to_file("\nInteractive remediation complete.")

        # Re-run scan to get final report
        write_to_file("\nRe-running scan to get final report...")
        final_log = run_all_checks({**config, 'password': password}, utils)
        
        write_to_file("\nInteractive remediation session complete.")
        write_to_file("Final results will be displayed below.")
        
        # Cleanup
        cursor.close(); conn.close()
        
        # Return the final scan results to main.py for consistent reporting
        return final_log

    except pyodbc.Error as ex:
        write_to_file(f"[CRIT] MS-SQL connection error: {ex}")
        return []
    except Exception as e:
        write_to_file(f"[CRIT] Unexpected error in remediation: {e}")
        return []

def run_all_checks(config: Dict[str, Any], utils: Any) -> List[str]:
    """
    Connects to MS-SQL and runs all MS-SQL specific checks.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary with connection details.
        utils (Any): Utils module reference.
    
    Returns:
        List[str]: Report log with all check results.
    """
    write_to_file = utils.write_to_file # Get helper from main
    report_log = []

    try:
        # --- 1. Get Config ---
        server = config.get('server', 'localhost')
        database = config.get('database', 'master')
        username = config.get('username', 'sa')
        password = config.get('password', None)

        if not password:
            password = getpass.getpass(f"Enter password for MS-SQL user '{username}': ")

        # --- 2. Build Connection String ---
        conn_string = (
            f"DRIVER={config.get('driver')};"
            f"SERVER={server};"
            f"DATABASE={database};"
            f"UID={username};"
            f"PWD={password};"
            "TrustServerCertificate=yes;"
            "Encrypt=yes;"
        )
        
        # --- 3. Connect ---
        write_to_file(f"Connecting to MS-SQL Server {server}...")
        conn = pyodbc.connect(conn_string)
        cursor = conn.cursor()
        write_to_file("Connected successfully.\n")

        # --- 4. Run All Checks ---
        check_xp_cmdshell(cursor, report_log, utils)
        check_clr_enabled(cursor, report_log, utils)
        check_ad_hoc_queries(cursor, report_log, utils)
        check_database_mail(cursor, report_log, utils)
        check_ole_automation(cursor, report_log, utils)
        check_sa_login(cursor, report_log, utils)
        check_sa_renamed(cursor, report_log, utils)
        check_authentication_mode(cursor, report_log, utils)
        review_sql_logins(cursor, report_log, utils)
        check_linked_servers(cursor, report_log, utils)
        check_current_connection_encryption(cursor, report_log, utils)
        check_sysadmin_members(cursor, report_log, utils)
        
        # ... (winreg check for tls) ...
            
        check_login_auditing(cursor, report_log, utils)
        check_sql_server_audit(cursor, report_log, utils)
        check_tde_encryption(cursor, report_log, utils)
        check_backup_encryption(cursor, report_log, utils)
        check_network_exposure(report_log, utils)

        # --- 5. Cleanup ---
        cursor.close()
        conn.close()

    except pyodbc.Error as ex:
        write_to_file(f"[CRIT] MS-SQL connection error: {ex}")
    except Exception as e:
        write_to_file(f"[CRIT] Unexpected error in MS-SQL checker: {e}")

    return report_log

def run_mssql(config: Dict[str, Any], utils: Any) -> List[str]:
    """
    Entry wrapper: if config['interactive_remediation'] is True, run remediation mode;
    otherwise run the standard checks.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary.
        utils (Any): Utils module reference.
    
    Returns:
        List[str]: Report log (empty list in remediation mode).
    """
    if 'interactive_remediation' not in config:
        # Fallback prompt if caller did not choose mode explicitly
        utils.write_to_file("Select mode:\n  1) Scan only\n  2) Interactive remediation")
        choice = input("Enter choice [1/2] (default 1): ").strip()
        config['interactive_remediation'] = (choice == '2')

    if config.get('interactive_remediation'):
        return run_interactive_remediation(config, utils)
    return run_all_checks(config, utils)

def prompt_mode_and_run(config: Dict[str, Any], utils: Any) -> List[str]:
    """
    Prompt the user to choose mode before running (scan vs interactive remediation).
    If config['interactive_remediation'] is already set, it will be respected.
    
    Args:
        config (Dict[str, Any]): Configuration dictionary.
        utils (Any): Utils module reference.
    
    Returns:
        List[str]: Report log from run_mssql().
    """
    if 'interactive_remediation' not in config:
        utils.write_to_file("Select mode:\n  1) Scan only\n  2) Interactive remediation")
        choice = input("Enter choice [1/2] (default 1): ").strip()
        if choice == '2':
            config['interactive_remediation'] = True
        else:
            config['interactive_remediation'] = False
        return run_mssql(config, utils)

# SECURITY CHECK FUNCTIONS - SURFACE AREA CONFIGURATION
def check_xp_cmdshell(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks if xp_cmdshell is enabled.
    Results are added to the report_log list.
    """
    # Get the formatting function
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking xp_cmdshell ---")
    
    try:
        cursor.execute("""
            SELECT CAST(value_in_use AS INT)
            FROM sys.configurations
            WHERE name = 'xp_cmdshell'
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("xp_cmdshell Status", "ENABLED",
                                       "Disable if not explicitly required. Allows OS command execution.", "CRIT")
                )
            else:
                report_log.append(
                    format_check_result("xp_cmdshell Status", "Disabled", "", "GOOD")
                )
        else:
            report_log.append(
                format_check_result("xp_cmdshell Status", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("xp_cmdshell Status", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("xp_cmdshell Status", f"Unexpected error: {e}", "", "WARN")
        )

def check_clr_enabled(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks if CLR is enabled.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking CLR Integration ---")
    
    try:
        cursor.execute("""
            SELECT CAST(value_in_use AS INT)
            FROM sys.configurations
            WHERE name = 'clr enabled'
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("CLR Integration", "ENABLED",
                                       "Disable if not using CLR assemblies. Increases attack surface.", "WARN")
                )
            else:
                report_log.append(
                    format_check_result("CLR Integration", "Disabled", "", "GOOD")
                )
        else:
            report_log.append(
                format_check_result("CLR Integration", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("CLR Integration", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("CLR Integration", f"Unexpected error: {e}", "", "WARN")
        )

def check_ad_hoc_queries(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks CIS 2.1: Ensure 'Ad Hoc Distributed Queries' is set to '0'
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Ad Hoc Distributed Queries (CIS 2.1) ---")
    
    try:
        # This query is from the CIS Benchmark Audit Procedure
        cursor.execute("""
            SELECT CAST(value_in_use AS INT)
            FROM sys.configurations
            WHERE name = 'Ad Hoc Distributed Queries'
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("Ad Hoc Distributed Queries", "ENABLED",
                                       "Disable this. It allows users to query external data sources, increasing risk.", "CRIT")
                )
            else:
                report_log.append(
                    format_check_result("Ad Hoc Distributed Queries", "Disabled", "", "GOOD")
                )
        else:
            report_log.append(
                format_check_result("Ad Hoc Distributed Queries", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Ad Hoc Distributed Queries", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Ad Hoc Distributed Queries", f"Unexpected error: {e}", "", "WARN")
        )

def check_database_mail(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks CIS 2.4: Ensure 'Database Mail XPs' is set to '0'
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Database Mail XPs (CIS 2.4) ---")
    
    try:
        # This query is from the CIS Benchmark Audit Procedure
        cursor.execute("""
            SELECT CAST(value_in_use AS INT)
            FROM sys.configurations
            WHERE name = 'Database Mail XPs'
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("Database Mail XPs", "ENABLED",
                                       "Disable if not required. Can be used to exfiltrate data.", "WARN")
                )
            else:
                report_log.append(
                    format_check_result("Database Mail XPs", "Disabled", "", "GOOD")
                )
        else:
            report_log.append(
                format_check_result("Database Mail XPs", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Database Mail XPs", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Database Mail XPs", f"Unexpected error: {e}", "", "WARN")
        )

def check_ole_automation(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks CIS 2.5: Ensure 'Ole Automation Procedures' is set to '0'
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Ole Automation Procedures (CIS 2.5) ---")
    
    try:
        # This query is from the CIS Benchmark Audit Procedure
        cursor.execute("""
            SELECT CAST(value_in_use AS INT)
            FROM sys.configurations
            WHERE name = 'Ole Automation Procedures'
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("Ole Automation Procedures", "ENABLED",
                                       "Disable this. Critical risk. Allows SQL to run external OS functions.", "CRIT")
                )
            else:
                report_log.append(
                    format_check_result("Ole Automation Procedures", "Disabled", "", "GOOD")
                )
        else:
            report_log.append(
                format_check_result("Ole Automation Procedures", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Ole Automation Procedures", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Ole Automation Procedures", f"Unexpected error: {e}", "", "WARN")
        )

# SECURITY CHECK FUNCTIONS - AUTHENTICATION & ACCESS CONTROL
def check_sa_login(cursor: Any, report_log: List[str], utils: Any) -> None:
    """
    Checks sa login status.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking 'sa' Login Status ---")
    
    try:
        # Use SID 0x01 which is always 'sa'
        cursor.execute("""
            SELECT name, is_disabled
            FROM sys.sql_logins
            WHERE sid = 0x01
        """)
        row = cursor.fetchone()
        if row:
            if row.is_disabled:
                report_log.append(
                    format_check_result("'sa' Account Status", "Disabled", "", "GOOD")
                )
            else:
                report_log.append(
                    format_check_result("'sa' Account Status", f"ENABLED (Login: {row.name})",
                                       "Disable 'sa' and use specific admin accounts. Rename if must be enabled.", "CRIT")
                )
        else:
            # This should realistically never happen for SID 0x01
            report_log.append(
                format_check_result("'sa' Account Status", "Not found (unexpected).", "", "WARN")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("'sa' Account Status", f"Error checking: {ex}", "Check permissions.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("'sa' Account Status", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check if 'sa' login is renamed ----------
def check_sa_renamed(cursor, report_log, utils):
    """
    Checks CIS 2.14: Ensure the 'sa' Login Account has been renamed
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking 'sa' Login Name (CIS 2.14) ---")
    
    try:
        # This query finds the login with the 'sa' SID (0x01)
        # and checks its current name.
        cursor.execute("""
            SELECT name
            FROM sys.server_principals
            WHERE sid = 0x01
        """)
        row = cursor.fetchone()
        if row:
            sa_name = row[0]
            if sa_name.lower() == 'sa':
                report_log.append(
                    format_check_result("'sa' Account Name", f"NOT Renamed (Name is 'sa')",
                                       "Rename the 'sa' account to a non-default name to reduce brute-force attacks.", "WARN")
                )
            else:
                report_log.append(
                    format_check_result("'sa' Account Name", f"Renamed (Name is '{sa_name}')", "", "GOOD")
                )
        else:
            # This should realistically never happen
            report_log.append(
                format_check_result("'sa' Account Name", "Could not find 'sa' principal (sid 0x01).", "", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("'sa' Account Name", f"Error checking: {ex}", "Check permissions.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("'sa' Account Name", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check Server Authentication Mode ----------
def check_authentication_mode(cursor, report_log, utils):
    """
    Checks CIS 3.1: Ensure 'Server Authentication' is set to 'Windows Authentication Mode'
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Server Authentication Mode (CIS 3.1) ---")
    
    try:
        # This query is from the CIS Benchmark Audit Procedure
        # 1 = Windows Authentication Mode
        # 0 = Mixed Mode (SQL Server and Windows Authentication)
        cursor.execute("""
            SELECT CASE SERVERPROPERTY('IsIntegratedSecurityOnly')
                WHEN 1 THEN 1
                WHEN 0 THEN 0
            END AS AuthMode;
        """)
        row = cursor.fetchone()
        if row:
            status = row[0]
            if status == 1:
                report_log.append(
                    format_check_result("Server Authentication", "Windows Authentication Mode", "", "GOOD")
                )
            else:
                report_log.append(
                    format_check_result("Server Authentication", "Mixed Mode (Windows and SQL Authentication)",
                                       "Use 'Windows Authentication Mode' only. Mixed Mode is less secure and increases attack surface.", "WARN")
                )
        else:
            report_log.append(
                format_check_result("Server Authentication", "Could not determine status.", "Check query/permissions.", "INFO")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Server Authentication", f"Error checking: {ex}", "Check permissions/query.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Server Authentication", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Review SQL logins ----------
def review_sql_logins(cursor, report_log, utils):
    """
    Reviews SQL logins.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Reviewing Logins ---")
    
    try:
        cursor.execute("""
            SELECT name, is_disabled,
                   is_policy_checked,
                   is_expiration_checked,
                   type_desc
            FROM sys.sql_logins
            ORDER BY name; -- Added for consistent output
        """)
        logins = cursor.fetchall()
        report_log.append(f"[INFO] Found {len(logins)} total logins.")
        report_log.append("-" * SEPARATOR_LENGTH)
        if not logins:
            report_log.append("   No logins found (or insufficient permissions).")
            return

        for row in logins:
            name, is_disabled, is_policy_checked, is_expiration_checked, type_desc = row
            status_notes = []
            if is_disabled: status_notes.append("DISABLED")

            report_log.append(f"   Login: {name} ({type_desc}) {'[' + ', '.join(status_notes) + ']' if status_notes else ''}")

            if type_desc == 'SQL_LOGIN':
                policy_status = "Yes" if is_policy_checked else "No"
                exp_status = "Yes" if is_expiration_checked else "No"
                report_log.append(f"      Password Policy Enforced: {policy_status}")
                report_log.append(f"      Password Expiration Enabled: {exp_status}")
                if not is_disabled and name != 'sa' and (not is_policy_checked or not is_expiration_checked):
                    report_log.append("      └── [WARN] Recommend enforcing policy and expiration for active SQL logins.")
            elif type_desc.startswith('WINDOWS'):
                report_log.append("      (Policy managed by Windows/AD)")
            else:
                report_log.append("      (Policy not applicable)")
            report_log.append("-" * SEPARATOR_LENGTH)

    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Login Review", f"Error assessing logins: {ex}", "", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Login Review", f"Unexpected error assessing logins: {e}", "", "WARN")
        )

# ---------- Check for Linked Servers ----------
def check_linked_servers(cursor, report_log, utils):
    """
    Checks for linked servers.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Linked Servers ---")
    
    try:
        cursor.execute("SELECT name, product, provider FROM sys.servers WHERE is_linked = 1 ORDER BY name;")
        rows = cursor.fetchall()
        if rows:
            server_list = [f"{row.name} (Product: {row.product or 'N/A'}, Provider: {row.provider or 'N/A'})" for row in rows]
            report_log.append(
                format_check_result("Linked Servers Found", f"{len(rows)}: {'; '.join(server_list)}",
                                   "Review necessity, security context, and permissions for each.", "WARN")
            )
        else:
            report_log.append(
                format_check_result("Linked Servers", "None found.", "", "GOOD")
            )
    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Linked Servers", f"Error checking: {ex}", "Check permissions.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Linked Servers", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check if CURRENT connection uses encryption ----------
def check_current_connection_encryption(cursor, report_log, utils):
    """
    Checks if current connection uses encryption.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Connection Encryption (Current Session) ---")
    
    try:
        # Get the session ID for the current connection
        cursor.execute("SELECT @@SPID;")
        spid_row = cursor.fetchone()
        if not spid_row:
            report_log.append(
                format_check_result("Current Connection Encryption", "Could not get current SPID.", "", "INFO")
            )
            return
        spid = spid_row[0]

        # Check encryption status for this SPID
        cursor.execute("SELECT encrypt_option FROM sys.dm_exec_connections WHERE session_id = ?;", spid)
        row = cursor.fetchone()
        if row:
            encrypt_option = row[0] # Should be 'TRUE' or 'FALSE' as strings
            if encrypt_option == 'TRUE':
                report_log.append(
                    format_check_result("Current Connection Encryption", "Encrypted (TLS/SSL)",
                                       "Good. Note: This only confirms *this* connection is encrypted, not server's overall support/enforcement.", "GOOD")
                )
            else: # Should be 'FALSE'
                report_log.append(
                    format_check_result("Current Connection Encryption", "NOT Encrypted",
                                       "CRITICAL: Configure server/client to force encryption (e.g., 'Force Protocol Encryption' server-side).", "CRIT")
                )
        else:
            report_log.append(
                format_check_result("Current Connection Encryption", f"Could not find connection info for SPID {spid}.", "", "INFO")
            )
    except pyodbc.Error as ex:
        # Common cause: Missing VIEW SERVER STATE permission
        report_log.append(
            format_check_result("Current Connection Encryption", f"Error checking: {ex}", "Check permissions (VIEW SERVER STATE required for dm_exec_connections).", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Current Connection Encryption", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check sysadmin role members ----------
def check_sysadmin_members(cursor, report_log, utils):
    """
    Checks sysadmin role members.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Sysadmin Role Members ---")
    
    sa_is_enabled = False # Default assumption
    try:
        # Quick check if 'sa' is enabled to refine recommendation
        cursor.execute("SELECT is_disabled FROM sys.sql_logins WHERE sid = 0x01;")
        sa_row = cursor.fetchone()
        if sa_row and sa_row.is_disabled == 0:
            sa_is_enabled = True
    except:
        pass # Ignore errors here, just proceed without the refined check

    try:
        # Query joining principals for clarity on type
        query = """
            SELECT p.name AS LoginName, p.type_desc AS LoginType
            FROM sys.server_role_members rm
            JOIN sys.server_principals r ON rm.role_principal_id = r.principal_id
            JOIN sys.server_principals p ON rm.member_principal_id = p.principal_id
            WHERE r.name = 'sysadmin'
            ORDER BY p.name;
        """
        cursor.execute(query)
        rows = cursor.fetchall()
        admin_list = [f"{row.LoginName} ({row.LoginType})" for row in rows]
        admin_count = len(rows)

        # Refine count if 'sa' is the only member and it's disabled
        effective_admin_count = admin_count
        if admin_count == 1 and rows[0].LoginName == 'sa' and not sa_is_enabled:
            effective_admin_count = 0

        if effective_admin_count > 0:
            # Add note if 'sa' is enabled and listed
            sa_note = ""
            if sa_is_enabled and 'sa (SQL_LOGIN)' in admin_list:
                sa_note = " ('sa' is enabled!)"

            report_log.append(
                format_check_result("Sysadmin Role Members", f"{admin_count} found: {', '.join(admin_list)}{sa_note}",
                                   "Minimize sysadmin members. Grant specific permissions instead. Review each member.", "WARN")
            )
        else:
            # This covers case where only 'sa' is member and it's disabled
            status_msg = "None found (excluding 'sa' if disabled)." if admin_count > 0 else "None found."
            report_log.append(
                format_check_result("Sysadmin Role Members", status_msg, "", "GOOD")
            )

    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Sysadmin Role Members", f"Error checking: {ex}", "Check permissions.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Sysadmin Role Members", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check Server TLS/SSL Protocol Support (Windows Registry) ----------
def check_server_tls_support(report_log, utils):
    """
    Checks enabled TLS/SSL protocols in Windows Registry (SChannel).
    Requires the script to run ON the SQL Server machine as Administrator.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Server TLS/SSL Support (Requires Local Admin on Server) ---")

    # Check if running on Windows and winreg was imported
    if platform.system() != "Windows":
        report_log.append(
            format_check_result("Server TLS Check", "Skipped (Not running on Windows)", "", "INFO")
        )
        return
    if not winreg:
        report_log.append(
            format_check_result("Server TLS Check", "Skipped ('winreg' module not available)", "", "INFO")
        )
        return

    base_path = r"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols"
    protocols_to_check = {
        # Protocol Name: Recommended State (True=Enabled, False=Disabled)
        "SSL 3.0": False,
        "TLS 1.0": False,
        "TLS 1.1": False,
        "TLS 1.2": True,
        # "TLS 1.3": True # Add if checking on Win Server 2022 / Win 11+
    }
    results = {}

    try:
        for protocol, recommended_enabled in protocols_to_check.items():
            # Check Server subkey
            server_key_path = f"{base_path}\\{protocol}\\Server"
            enabled_value = None
            disabled_by_default = None
            key_exists = False
            protocol_status = "Unknown (Key Error)"

            try:
                # Open the 'Server' key for the protocol
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, server_key_path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    key_exists = True
                    # Try reading the 'Enabled' DWORD value
                    try:
                        enabled_value, _ = winreg.QueryValueEx(key, "Enabled")
                    except FileNotFoundError:
                        enabled_value = None # Value doesn't exist

                    # Try reading the 'DisabledByDefault' DWORD value
                    try:
                        disabled_by_default, _ = winreg.QueryValueEx(key, "DisabledByDefault")
                    except FileNotFoundError:
                        disabled_by_default = None # Value doesn't exist

                    # --- Interpretation Logic ---
                    if enabled_value == 0:
                        protocol_status = "Disabled (Explicitly: Enabled=0)"
                    elif disabled_by_default == 1:
                        if enabled_value == 1:
                            protocol_status = "Enabled (Explicitly: Enabled=1, overrides DisabledByDefault=1)"
                        else:
                            protocol_status = "Disabled (Implicitly: DisabledByDefault=1)"
                    elif enabled_value == 1:
                        protocol_status = "Enabled (Explicitly: Enabled=1)"
                    else:
                        # Neither explicitly disabled nor disabled by default. Follows OS default.
                        # Heuristic guess based on protocol (modern OS usually enables TLS 1.2+ by default)
                        if protocol in ["TLS 1.2", "TLS 1.3"]:
                            protocol_status = "Enabled (Likely OS Default)"
                        else:
                            protocol_status = "Disabled (Likely OS Default on modern OS)"

            except FileNotFoundError:
                # The 'Server' key for the protocol doesn't exist. Assume OS default.
                key_exists = False
                if protocol in ["TLS 1.2", "TLS 1.3"]:
                    protocol_status = "Enabled (Likely OS Default - Key Missing)"
                else:
                    protocol_status = "Disabled (Likely OS Default on modern OS - Key Missing)"
            except PermissionError:
                 protocol_status = "Error (Permission Denied to read registry)"
                 # Stop checking further protocols if permission is denied once
                 results[protocol] = {"status": protocol_status, "level": "WARN", "rec": "Run script as Administrator."}
                 break
            except Exception as reg_err:
                 protocol_status = f"Error (Registry access failed: {reg_err})"
                 results[protocol] = {"status": protocol_status, "level": "WARN", "rec": "Check registry access."}
                 continue # Try next protocol

            # Determine level and recommendation based on status vs. recommendation
            level = "INFO"
            recommendation = ""
            is_enabled = "enabled" in protocol_status.lower() # Simple check if the status string indicates enabled

            if "error" in protocol_status.lower() or "unknown" in protocol_status.lower():
                level = "WARN"
            elif is_enabled and not recommended_enabled:
                level = "CRIT" # E.g., SSL 3.0 is enabled
                recommendation = f"Disable {protocol} via registry (requires restart)."
            elif not is_enabled and recommended_enabled:
                level = "WARN" # E.g., TLS 1.2 is disabled
                recommendation = f"Enable {protocol} via registry (requires restart)."
            elif (is_enabled and recommended_enabled) or (not is_enabled and not recommended_enabled):
                level = "GOOD" # State matches recommendation

            results[protocol] = {"status": protocol_status, "level": level, "rec": recommendation}

        # Add results to report_log
        if not results:
            report_log.append(
                format_check_result("Server TLS Check", "No protocols checked or error occurred.", "", "WARN")
            )
        else:
            for protocol, data in results.items():
                report_log.append(
                    format_check_result(f"{protocol} Server Support", data["status"], data["rec"], data["level"])
                )

    except Exception as e:
        # Catch potential errors opening the base SCHANNEL key etc.
        report_log.append(
            format_check_result("Server TLS Check", f"Failed to perform check: {e}", "Ensure script runs as Admin on the server.", "WARN")
        )

# ---------- Reminder for Manual Network Checks ----------
def check_network_exposure(report_log, utils):
    """
    Checks network exposure.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Network Exposure (Manual Check Required) ---")
    
    report_log.append(
        format_check_result("TCP Port 1433 Exposure", "Requires external port scanning.",
                           "Ensure firewall restricts access to 1433/TCP only from trusted IPs. Avoid direct internet exposure.", "INFO")
    )
    report_log.append(
        format_check_result("SQL Server Browser Service", "Requires checking Windows Services (services.msc) or PowerShell.",
                           "Disable if not needed (e.g., all clients use static ports). Reduces information disclosure.", "INFO")
    )

# ---------- Check Legacy Login Auditing Level ----------
def check_login_auditing(cursor, report_log, utils):
    """
    Checks CIS 5.3: Ensure 'Login Auditing' is set to 'failed logins'
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Legacy Login Auditing (CIS 5.3) ---")
    
    # This check is more complex as it requires reading a registry key
    # via an (undocumented but standard) stored procedure.
    # We must use 'try...except' blocks carefully.
    
    audit_level_value = None
    try:
        # Create a temp table to hold the output of the sp
        cursor.execute("IF OBJECT_ID('tempdb..#AuditLevel') IS NOT NULL DROP TABLE #AuditLevel;")
        cursor.execute("CREATE TABLE #AuditLevel (ValueName NVARCHAR(128), Data INT);")
        
        # This sp reads the registry key for the 'AuditLevel'
        # 0 = None, 1 = Successful only, 2 = Failed only, 3 = Both
        cursor.execute("""
            INSERT INTO #AuditLevel (ValueName, Data)
            EXEC master.dbo.xp_instance_regread
                N'HKEY_LOCAL_MACHINE',
                N'SOFTWARE\\Microsoft\\MSSQLServer\\MSSQLServer',
                N'AuditLevel'
        """)
        
        row = cursor.execute("SELECT Data FROM #AuditLevel").fetchone()
        if row:
            audit_level_value = row[0]
            
        cursor.execute("DROP TABLE #AuditLevel;")

    except pyodbc.Error as ex:
        # This can fail if the user doesn't have permissions for xp_instance_regread
        report_log.append(
            format_check_result("Login Auditing", f"Error checking: {ex}", 
                               "Check permissions for 'xp_instance_regread'.", "WARN")
        )
        return
    except Exception as e:
        report_log.append(
            format_check_result("Login Auditing", f"Unexpected error: {e}", "", "WARN")
        )
        return

    # Now, interpret the value we read
    if audit_level_value is not None:
        if audit_level_value == 2:
            report_log.append(
                format_check_result("Login Auditing", "Failed logins only", "", "GOOD")
            )
        elif audit_level_value == 0:
            report_log.append(
                format_check_result("Login Auditing", "None",
                                   "Set to 'Failed logins only' to detect brute-force attacks (CIS 5.3).", "CRIT")
            )
        elif audit_level_value == 1:
            report_log.append(
                format_check_result("Login Auditing", "Successful logins only",
                                   "Set to 'Failed logins only'. Successful logins should be captured via SQL Server Audit (CIS 5.4).", "WARN")
            )
        elif audit_level_value == 3:
            report_log.append(
                format_check_result("Login Auditing", "Both failed and successful logins",
                                   "Set to 'Failed logins only'. Logging successful logins here creates noise in the error log (CIS 5.3).", "WARN")
            )
        else:
            report_log.append(
                format_check_result("Login Auditing", f"Unknown value ({audit_level_value})", "Investigate manually.", "INFO")
            )
    else:
        report_log.append(
            format_check_result("Login Auditing", "Could not determine status.", "Check query/permissions.", "INFO")
        )

# ---------- Check SQL Server Audit Configuration ----------
def check_sql_server_audit(cursor, report_log, utils):
    """
    Checks CIS 5.4: Ensure 'SQL Server Audit' is set to capture key events
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking SQL Server Audit (CIS 5.4) ---")

    # CIS 5.4 recommends auditing many groups.
    # For this tool, we will check for the most critical ones:
    # - SUCCESSFUL_LOGIN_GROUP
    # - FAILED_LOGIN_GROUP
    # - SERVER_ROLE_MEMBER_CHANGE_GROUP (tracks 'sysadmin' changes)
    
    required_audits = {
        'SUCCESSFUL_LOGIN_GROUP': False,
        'FAILED_LOGIN_GROUP': False,
        'SERVER_ROLE_MEMBER_CHANGE_GROUP': False
    }

    try:
        # This query joins the audit itself (S), the specification (SA),
        # and the details (SAD) to find enabled audits for key actions.
        cursor.execute("""
            SELECT 
                SAD.audit_action_name
            FROM sys.server_audits AS S
            JOIN sys.server_audit_specifications AS SA
                ON S.audit_guid = SA.audit_guid
            JOIN sys.server_audit_specification_details AS SAD
                ON SA.server_specification_id = SAD.server_specification_id
            WHERE
                S.is_state_enabled = 1 
                AND SA.is_state_enabled = 1
                AND SAD.audit_action_name IN (
                    'SUCCESSFUL_LOGIN_GROUP',
                    'FAILED_LOGIN_GROUP',
                    'SERVER_ROLE_MEMBER_CHANGE_GROUP'
                )
            GROUP BY SAD.audit_action_name;
        """)
        
        rows = cursor.fetchall()
        
        if not rows:
            report_log.append(
                format_check_result("SQL Server Audit", "NOT CONFIGURED",
                                   "Enable a Server Audit to capture successful logins, failed logins, and role changes (CIS 5.4).", "CRIT")
            )
            return

        for row in rows:
            if row.audit_action_name in required_audits:
                required_audits[row.audit_action_name] = True
        
        # Check results
        missing_audits = [name for name, found in required_audits.items() if not found]

        if not missing_audits:
            report_log.append(
                format_check_result("SQL Server Audit", "Configured (Found all critical groups)", "", "GOOD")
            )
        else:
            report_log.append(
                format_check_result("SQL Server Audit", f"Partially Configured. Missing: {', '.join(missing_audits)}",
                                   "Ensure an enabled audit specification is capturing all critical groups (CIS 5.4).", "WARN")
            )

    except pyodbc.Error as ex:
        # This can fail if the user doesn't have VIEW SERVER STATE or ALTER ANY SERVER AUDIT permission
        report_log.append(
            format_check_result("SQL Server Audit", f"Error checking: {ex}", 
                               "Check permissions (VIEW SERVER STATE, ALTER ANY SERVER AUDIT).", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("SQL Server Audit", f"Unexpected error: {e}", "", "WARN")
        )
        
# ---------- Check for Transparent Data Encryption (TDE) ----------
def check_tde_encryption(cursor, report_log, utils):
    """
    Checks CIS 7.5: Ensure Databases are Encrypted with TDE
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Database Encryption (TDE) (CIS 7.5) ---")
    
    try:
        # 1 = Encrypted with TDE. 0 = Not Encrypted.
        # We check all user databases (database_id > 4)
        cursor.execute("""
            SELECT name, is_encrypted
            FROM sys.databases
            WHERE database_id > 4
            ORDER BY name;
        """)
        rows = cursor.fetchall()
        if not rows:
            report_log.append(
                format_check_result("Database Encryption (TDE)", "No user databases found.", "", "INFO")
            )
            return

        unencrypted_dbs = []
        for row in rows:
            if not row.is_encrypted:
                unencrypted_dbs.append(row.name)

        if not unencrypted_dbs:
            report_log.append(
                format_check_result("Database Encryption (TDE)", "All user databases are encrypted.", "", "GOOD")
            )
        else:
            report_log.append(
                format_check_result("Database Encryption (TDE)", f"NOT Encrypted: {', '.join(unencrypted_dbs)}",
                                   "Encrypt all user databases with TDE to meet BNM RMiT and PDPA data-at-rest requirements.", "CRIT")
            )

    except pyodbc.Error as ex:
        report_log.append(
            format_check_result("Database Encryption (TDE)", f"Error checking: {ex}", "Check permissions.", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Database Encryption (TDE)", f"Unexpected error: {e}", "", "WARN")
        )

# ---------- Check for Backup Encryption ----------
def check_backup_encryption(cursor, report_log, utils):
    """
    Checks CIS 7.3: Ensure Database Backups are Encrypted
    Note: This checks the *history* of recent backups. It also
    passes if TDE is on, as TDE backups are encrypted by default.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Database Backup Encryption (CIS 7.3) ---")
    
    try:
        # This query checks the backup history (in msdb) and joins
        # with TDE status. Backups are considered "encrypted" if
        # EITHER TDE is on (is_encrypted=1) OR the backup
        # itself was made with the ENCRYPTION flag (key_algorithm is NOT NULL).
        cursor.execute("""
            SELECT
                d.name AS database_name,
                b.backup_finish_date
            FROM msdb.dbo.backupset AS b
            INNER JOIN sys.databases AS d
                ON b.database_name = d.name
            WHERE
                d.database_id > 4
                AND d.is_encrypted = 0 
                AND b.key_algorithm IS NULL
                AND b.backup_finish_date > GETDATE() - 30 
            GROUP BY d.name, b.backup_finish_date
            ORDER BY b.backup_finish_date DESC;
        """)
        
        rows = cursor.fetchall()
        
        if not rows:
            report_log.append(
                format_check_result("Backup Encryption", "All recent user database backups are encrypted (or TDE is enabled).", "", "GOOD")
            )
        else:
            unencrypted_backups = list(set([row.database_name for row in rows]))
            report_log.append(
                format_check_result("Backup Encryption", f"Unencrypted backups found for: {', '.join(unencrypted_backups)}",
                                   "Ensure all backups are made with the 'ENCRYPTION' option, or enable TDE on the database.", "CRIT")
            )

    except pyodbc.Error as ex:
        # This will fail if user cannot read msdb.dbo.backupset
        report_log.append(
            format_check_result("Backup Encryption", f"Error checking: {ex}", 
                               "Check permissions (must be able to read 'msdb.dbo.backupset').", "WARN")
        )
    except Exception as e:
        report_log.append(
            format_check_result("Backup Encryption", f"Unexpected error: {e}", "", "WARN")
        )