# Database Security and Compliance Auditor

## Description
This is a Python tool that checks the security settings of a database. It connects to a target database, runs a list of security checks, and prints a report to the console.

The checks are based on industry standards (CIS Benchmarks). The tool is designed to show how technical settings map to Malaysian compliance requirements, such as the PDPA (Act 709), Bank Negara Malaysia's RMiT policy, and the Cybersecurity Act 2024.

## Features
*   **Security Auditing:** Runs a series of checks for common security misconfigurations.
*   **Compliance Mapping:** Explains how technical settings (like "CLR Enabled") relate to legal requirements (like PDPA or BNM RMiT).
*   **Extensible Design:** Built with a "plug-in" architecture. You can add new database types (like Oracle, MySQL) without changing the main application.
*   **Config-Driven:** The entire tool is controlled by a simple `config.ini` file.

## How It Works (Architecture)
This tool is separated into a "core engine" and "plug-ins". This design makes it extensible.

### `main.py` (The Engine)
*   This is the main script you run.
*   It has no code for any specific database.
*   Its only job is to read the `config.ini` file.

### `config.ini` (The "Settings")
*   This file tells the engine which database to check (e.g., `target_db = mssql`).
*   It also stores all the connection details (server, username, etc.) for each database.

### `checkers/` (The "Plug-ins" Folder)
*   This folder holds the plug-in files for each database.
*   `main.py` dynamically loads the correct plug-in from this folder based on the `config.ini` setting.

### `checkers/check_mssql.py` (An Example Plug-in)
*   This file contains all the code for checking MS-SQL Server.
*   It knows how to connect using `pyodbc`, what SQL queries to run, and what to check.

### `checkers/check_mongodb.py` (An Example Plug-in)
*   This file contains all the code for checking MongoDB.
*   It knows how to connect using `pymongo` and what admin commands to run.

## Prerequisites
You must have Python 3.x installed.

The required Python libraries are listed in `requirements.txt`:
pyodbc
pymongo

## How to Use
1.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    (You may also need to install the [Microsoft ODBC Driver 18 for SQL Server](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server) separately if it is not on your system).

2.  **Configure the Tool:**
    *   Open the `config.ini` file in a text editor.
    *   In the `[main]` section, set `target_db` to the database type you want to check (e.g., `mssql` or `mongodb`).
    *   Fill in the connection details for that database's section (e.g., in `[mssql]`, set the `server`, `database`, and `username`).
    *   **Password:** If you leave the password field blank, the tool will securely prompt you for it when it runs.

3.  **Run the Tool:**
    ```bash
    python main.py
    ```
    The tool will read the config, load the correct plug-in, and print the security report to your console.

## How to Add a New Database (e.g., Oracle)
The tool is designed to be easily extended.

1.  **Install Driver:** Install the new database driver.
    ```bash
    pip install cx_Oracle
    ```

2.  **Edit `config.ini`:** Add a new section for your database.
    ```ini
    [oracle]
    module_name = checkers.check_oracle
    service_name = ORCL
    host = 192.168.1.100
    port = 1521
    username = system
    ```

3.  **Create Plug-in:** Create the new file `checkers/check_oracle.py`.

4.  **Write Plug-in Code:** In that new file, you must create one main function called `run_all_checks(config, utils)`. This function will contain all your Oracle-specific logic for connecting and running checks.

The `main.py` engine will automatically find and run your new plug-in if you set `target_db = oracle` in the config file. You do not need to edit `main.py` at all.


## Compliance Mapping Table

| CIS ID | CIS Recommendation | My Tool's Function | Compliance Map (PDPA 2010) | Compliance Map (BNM RMiT) | Compliance Map (Cybersecurity Act 2024) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Section 2** | **Surface Area Reduction** | | | | |
| 2.1 | Ad Hoc Distributed Queries' | `check_ad_hoc_queries` | Security Principle (Sec. 9): A "practical step" to prevent "unauthorised access" to other linked systems. | Access Control: Enforces the Principle of Least Privilege. Prevents a compromised SQL login from being used to attack other network resources. | CNII Duties: A technical measure to reduce the attack surface of a critical national asset. |
| 2.2 | CLR Enabled' | `check_clr_enabled` | Security Principle (Sec. 9): Prevents "unauthorised access... or alteration" of the host server by disallowing external code. | Access Control: Enforces separation of duties between the database and the OS, a core part of robust access control. | CNII Duties: A mandatory hardening step to ensure the integrity of the critical system. |
| 2.4 | Database Mail XPs' | `check_database_mail` | Security Principle (Sec. 9): Directly prevents "unauthorised... disclosure". This check closes a potential channel for data exfiltration. | Data Leakage Prevention: Supports RMiT's goal of protecting data confidentiality and preventing data breaches. | CNII Duties: A technical control to prevent data exfiltration from a critical system. |
| 2.5 | Ole Automation Procedures' | `check_ole_automation` | Security Principle (Sec. 9): A "practical step" to prevent "unauthorised access" to the underlying OS, which could lead to data loss. | Access Control: Enforces the Principle of Least Privilege and separation of duties (same as CLR). | CNII Duties: A critical hardening step to prevent privilege escalation on a CNII asset. |
| **Section 3** | **Authentication & Authorization** | | | | |
| 2.13 | 'sa' Login Account is 'Disabled' | `check_sa_login` | Security Principle (Sec. 9): A fundamental "practical step" to prevent "unauthorised access" using a well-known default account. | S 10.61 (a): "Access controls... are effectively managed". Disabling default admin accounts is the definition of effective management. | CNII Duties: A non-negotiable baseline security measure for any critical system. |
| 2.14 | 'sa' Login Account is renamed | `check_sa_renamed` | Security Principle (Sec. 9): A "practical step" (defense-in-depth) that makes it harder for attackers to guess credentials. | S 10.61 (a): Part of a robust "access control" strategy to defend against brute-force attacks. | CNII Duties: A recommended hardening measure to protect against common attack vectors. |
| 3.1 | 'Server Authentication' is 'Windows Auth' | `check_authentication_mode` | Security Principle (Sec. 9): Enforces a stronger, centralized authentication method, a "practical step" over weaker, separate SQL passwords. | MFA Requirement: The 2023 RMiT update denotes MFA as a "standard requirement". Enforcing Windows-only Auth is the foundational enabler for this, as MFA is applied via the Windows (Active Directory) domain. | CNII Duties: Supports the requirement for strong, modern authentication on critical infrastructure. |
| 3.12 | 'SYSADMIN' Role is Limited | `check_sysadmin_members` | Security Principle (Sec. 9): A critical "practical step" to ensure that only a minimal number of users can access all personal data. | Principle of Least Privilege: This check is the primary evidence for this RMiT principle. It allows an auditor to see who has privileged access. | CNII Duties: Direct audit of privileged access, a key requirement for securing critical systems. |
| **Section 5** | **Auditing & Logging** | | | | |
| 5.3 | 'Login Auditing' is 'failed logins' | `check_login_auditing` | Security Principle (Sec. 9): A "practical step" to detect "unauthorised... access" attempts. | S 10.61 (b): "User activities... are logged for audit and investigations". This check ensures brute-force attacks are logged. | CNII Duties: A mandatory control for incident detection and response. |
| 5.4 | 'SQL Server Audit' is configured | `check_sql_server_audit` | Security Principle (Sec. 9): Creates a "practical step" for a robust audit trail to investigate any "unauthorised... disclosure." | S 10.61 (b): This is the modern implementation of this rule, ensuring "user activities... are logged for audit" in a dedicated, secure log. | CNII Duties: Provides the primary, modern audit trail required for forensic investigation after a cyber incident. |
| **Section 7** | **Encryption** | | | | |
| NEW7.3 | Database Backups are Encrypted | `check_backup_encryption` | Security Principle (Sec. 9): A critical "practical step to protect... from any loss... or unauthorised... disclosure" of backup files. | Cryptography: This directly supports RMiT's requirement for strong cryptographic controls to protect data, especially when backups are moved off-site. | CNII Duties: A mandatory measure to ensure data confidentiality, even if the backup media is stolen. |
| NEW7.5 | Databases are Encrypted (TDE) | `check_tde_encryption` | Security Principle (Sec. 9): The strongest "practical step" to protect data from "unauthorised access" if the physical server or drives are stolen. | Cryptography / Data-at-Rest: This is the primary control for RMiT's requirement to encrypt sensitive data-at-rest. | CNII Duties: The core technical control for ensuring the confidentiality of data on a critical system. |
