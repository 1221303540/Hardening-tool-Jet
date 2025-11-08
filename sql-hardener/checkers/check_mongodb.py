#!/usr/bin/env python3
import getpass
from typing import Dict, List, Any
from pymongo import MongoClient, errors
from constants import MONGODB_TIMEOUT_MS, SEPARATOR_LENGTH

# This is the main "entry point" for this plug-in.
# The main.py engine will call this function.
def run_all_checks(config: Dict[str, str], utils: Any) -> List[str]:
    # Get the helper functions from the 'utils' module passed by main.py
    write_to_file = utils.write_to_file
    report_log = []

    try:
        # --- 1. Get Config ---
        connection_string = config.get('connection_string')
        username = config.get('username', None)
        password = config.get('password', None)
        
        if not password and username: # Prompt for password if username is provided but password is not
             password = getpass.getpass(f"Enter password for MongoDB user '{username}': ")

        # --- 2. Connect ---
        write_to_file(f"Connecting to MongoDB...")
        client = MongoClient(
            connection_string,
            username=username,
            password=password,
            serverSelectionTimeoutMS=MONGODB_TIMEOUT_MS
        )
        
        # Ping the server to verify connection and auth
        client.admin.command('ping')
        write_to_file("Connected successfully.\n")

        # --- 3. Run All MongoDB Checks ---
        # We pass the client, report_log, and utils to each check
        check_auth_enabled(client, report_log, utils)
        check_network_binding(client, report_log, utils)
        check_tls_enabled(client, report_log, utils)
        check_audit_logging(client, report_log, utils)
        check_auth_mechanisms(client, report_log, utils)

        # --- 4. Cleanup ---
        client.close()

    except errors.ConnectionFailure as ex:
        write_to_file(f"[CRIT] MongoDB connection error: {ex}")
    except errors.OperationFailure as ex:
        write_to_file(f"[CRIT] MongoDB authentication error: {ex}")
    except Exception as e:
        write_to_file(f"[CRIT] Unexpected error in MongoDB checker: {e}")

    return report_log


# All MongoDB-specific check functions are below
def check_auth_enabled(client: MongoClient, report_log: List[str], utils: Any) -> None:
    """
    Checks if MongoDB has authentication enabled (security.authorization).
    This is the MONGO-equivalent of CIS 3.1 (Windows Auth Mode).
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Authentication (MongoDB) ---")
    
    try:
        cmd_opts = client.admin.command("getCmdLineOpts")
        
        # Check if 'security.authorization' is present and set to 'enabled'
        auth_status = cmd_opts.get("parsed", {}).get("security", {}).get("authorization", "disabled")
        
        if auth_status == "enabled":
            report_log.append(
                format_check_result("MongoDB Authentication", "Enabled", "", "GOOD")
            )
        else:
            report_log.append(
                format_check_result("MongoDB Authentication", "DISABLED", 
                                   "CRITICAL: Enable 'security.authorization' in your config file. (Maps to BNM RMiT S 10.61(a))", "CRIT")
            )
    except Exception as e:
        report_log.append(
            format_check_result("MongoDB Authentication", f"Error checking: {e}", "Check user permissions (requires admin role).", "WARN")
        )

def check_network_binding(client: MongoClient, report_log: List[str], utils: Any) -> None:
    """
    Checks if MongoDB is bound to localhost only.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Network Binding (MongoDB) ---")
    
    try:
        cmd_opts = client.admin.command("getCmdLineOpts")
        # Default is '0.0.0.0' in many new versions if not set, which is insecure
        bind_ip = cmd_opts.get("parsed", {}).get("net", {}).get("bindIp", "0.0.0.0") 
        
        if "0.0.0.0" in str(bind_ip):
            report_log.append(
                format_check_result("Network Binding", f"INSECURE (Bound to {bind_ip})", 
                                   "Bind to '127.0.0.1' (localhost) to prevent public network exposure.", "CRIT")
            )
        else:
            report_log.append(
                format_check_result("Network Binding", f"Secure (Bound to {bind_ip})", "", "GOOD")
            )
    except Exception as e:
        report_log.append(
            format_check_result("Network Binding", f"Error checking: {e}", "Check user permissions.", "WARN")
        )

def check_tls_enabled(client: MongoClient, report_log: List[str], utils: Any) -> None:
    """
    Checks if MongoDB requires TLS/SSL (net.tls.mode).
    This is the MONGO-equivalent of your TLS/SSL check.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking TLS/SSL (MongoDB) ---")
    
    try:
        cmd_opts = client.admin.command("getCmdLineOpts")
        tls_mode = cmd_opts.get("parsed", {}).get("net", {}).get("tls", {}).get("mode", "disabled")
        
        if tls_mode == "requireTLS":
            report_log.append(
                format_check_result("TLS/SSL Mode", "requireTLS (Enabled)", "", "GOOD")
            )
        elif tls_mode == "preferTLS":
            report_log.append(
                format_check_result("TLS/SSL Mode", "preferTLS (Permits unencrypted)", 
                                   "Set TLS mode to 'requireTLS' to enforce encrypted connections.", "WARN")
            )
        else:
            report_log.append(
                format_check_result("TLS/SSL Mode", f"{tls_mode.upper()}", 
                                   "Set TLS mode to 'requireTLS' to enforce encrypted connections.", "CRIT")
            )
    except Exception as e:
        report_log.append(
            format_check_result("TLS/SSL Mode", f"Error checking: {e}", "Check user permissions.", "WARN")
        )

def check_audit_logging(client: MongoClient, report_log: List[str], utils: Any) -> None:
    """
    Checks if MongoDB has audit logging enabled.
    This is the MONGO-equivalent of CIS 5.4 and BNM RMiT S 10.61(b).
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Audit Logging (MongoDB) ---")
    
    try:
        cmd_opts = client.admin.command("getCmdLineOpts")
        
        # Check if 'auditLog.destination' is set to 'file', 'syslog', or 'console'
        audit_dest = cmd_opts.get("parsed", {}).get("auditLog", {}).get("destination", None)
        
        if audit_dest:
            report_log.append(
                format_check_result("Audit Logging", f"Enabled (Destination: {audit_dest})", "", "GOOD")
            )
        else:
            report_log.append(
                format_check_result("Audit Logging", "DISABLED", 
                                   "Enable 'auditLog.destination' in your config file. (Maps to BNM RMiT S 10.61(b))", "CRIT")
            )
    except Exception as e:
        report_log.append(
            format_check_result("Audit Logging", f"Error checking: {e}", "Check user permissions.", "WARN")
        )

def check_auth_mechanisms(client: MongoClient, report_log: List[str], utils: Any) -> None:
    """
    Checks for weak/deprecated authentication mechanisms.
    Results are added to the report_log list.
    """
    format_check_result = utils.format_check_result
    
    report_log.append("\n" + "-" * SEPARATOR_LENGTH)
    report_log.append("--- Checking Auth Mechanisms (MongoDB) ---")
    
    try:
        # Get the 'authenticationMechanisms' parameter from the server
        params = client.admin.command("getParameter", 1, authenticationMechanisms=1)
        mechanisms = params.get("authenticationMechanisms", [])
        
        if not mechanisms:
            report_log.append(
                format_check_result("Auth Mechanisms", "N/A (Authentication is likely disabled)", "", "INFO")
            )
            return

        weak_mechs = []
        if "MONGODB-CR" in mechanisms: # MONGODB-CR is deprecated and insecure
            weak_mechs.append("MONGODB-CR (Deprecated/Insecure)")
        if "PLAIN" in mechanisms: # PLAIN sends credentials in cleartext if not over TLS
            weak_mechs.append("PLAIN (Insecure without TLS)")
        
        if not weak_mechs:
            report_log.append(
                format_check_result("Auth Mechanisms", f"Secure ({', '.join(mechanisms)})", "", "GOOD")
            )
        else:
            report_log.append(
                format_check_result("Auth Mechanisms", f"WEAK MECHANISMS ENABLED: {', '.join(weak_mechs)}", 
                                   "Remove MONGODB-CR and PLAIN from 'authenticationMechanisms' setting.", "WARN")
            )
    except Exception as e:
        report_log.append(
            format_check_result("Auth Mechanisms", f"Error checking: {e}", "Check user permissions.", "WARN")
        )