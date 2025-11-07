from typing import Dict, List

# T-SQL Remediation Scripts
# Each key represents a remediation action, value is a list of T-SQL commands to execute
REMEDIATION_SQL: Dict[str, List[str]] = {
    # Surface Area Configuration
    "DISABLE_XP_CMDSHELL": [
        "EXEC sp_configure 'show advanced options', 1;",
        "RECONFIGURE;",
        "EXEC sp_configure 'xp_cmdshell', 0;",
        "RECONFIGURE;",
        "EXEC sp_configure 'show advanced options', 0;",
        "RECONFIGURE;",
    ],
    "DISABLE_CLR": [
        "EXEC sp_configure 'show advanced options', 1;",
        "RECONFIGURE;",
        "EXEC sp_configure 'clr enabled', 0;",
        "RECONFIGURE;",
        "EXEC sp_configure 'show advanced options', 0;",
        "RECONFIGURE;",
    ],
    "DISABLE_AD_HOC_DISTRIBUTED": [
        "EXEC sp_configure 'show advanced options', 1;",
        "RECONFIGURE;",
        "EXEC sp_configure 'Ad Hoc Distributed Queries', 0;",
        "RECONFIGURE;",
        "EXEC sp_configure 'show advanced options', 0;",
        "RECONFIGURE;",
    ],
    "DISABLE_DATABASE_MAIL_XPS": [
        "EXEC sp_configure 'show advanced options', 1;",
        "RECONFIGURE;",
        "EXEC sp_configure 'Database Mail XPs', 0;",
        "RECONFIGURE;",
        "EXEC sp_configure 'show advanced options', 0;",
        "RECONFIGURE;",
    ],
    "DISABLE_OLE_AUTOMATION": [
        "EXEC sp_configure 'show advanced options', 1;",
        "RECONFIGURE;",
        "EXEC sp_configure 'Ole Automation Procedures', 0;",
        "RECONFIGURE;",
        "EXEC sp_configure 'show advanced options', 0;",
        "RECONFIGURE;",
    ],
    # Logins and Authentication
    "DISABLE_SA_ACCOUNT": [
        "ALTER LOGIN [sa] DISABLE;",
    ],
    # Windows Authentication mode (requires service restart)
    "ENABLE_WINDOWS_AUTH_MODE": [
        "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        "N'Software\\Microsoft\\MSSQLServer\\MSSQLServer', N'LoginMode', REG_DWORD, 1;",
    ],
    # Legacy Login Auditing (requires service restart)
    "SET_AUDITLEVEL_FAILED_ONLY": [
        "EXEC xp_instance_regwrite N'HKEY_LOCAL_MACHINE', "
        "N'SOFTWARE\\Microsoft\\MSSQLServer\\MSSQLServer', N'AuditLevel', REG_DWORD, 2;",
    ],
}

