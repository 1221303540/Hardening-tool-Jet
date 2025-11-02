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
