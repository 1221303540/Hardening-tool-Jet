#!/usr/bin/env python3

import sys
import configparser
import importlib

# Import the helper functions. We will pass them to the plug-in.
import utils 

def main():
    """
    Main "engine" for the compliance tool.
    Reads config.ini to find and load the correct database plug-in.
    """
    utils.write_to_file("--- Database Security & Compliance Auditor ---")
    
    # --- 1. Read Configuration ---
    config = configparser.ConfigParser()
    try:
        config.read('config.ini')
        if not config.sections():
            utils.write_to_file("[CRITICAL] config.ini file not found or is empty.")
            sys.exit(1)
            
        # Find out which DB to target
        target_db_name = config.get('main', 'target_db', fallback=None)
        if not target_db_name:
            utils.write_to_file("[CRITICAL] 'target_db' not set in [main] section of config.ini")
            sys.exit(1)

        if target_db_name not in config:
            utils.write_to_file(f"[CRITICAL] Config section [{target_db_name}] not found in config.ini")
            sys.exit(1)
            
        target_config = config[target_db_name]

    except Exception as e:
        utils.write_to_file(f"[CRITICAL] Error reading config.ini: {e}")
        sys.exit(1)

    # --- 2. Dynamically Load the Plug-in ---
    try:
        module_name_to_load = target_config.get('module_name')
        if not module_name_to_load:
            utils.write_to_file(f"[CRITICAL] 'module_name' not set in [{target_db_name}] section.")
            sys.exit(1)
            
        utils.write_to_file(f"Loading plug-in: {module_name_to_load}...")
        
        # This is the "magic" of a plug-in architecture
        # It dynamically imports the module "checkers.check_mssql"
        checker_module = importlib.import_module(module_name_to_load)
        
    except ImportError:
        utils.write_to_file(f"[CRITICAL] Failed to import plug-in: {module_name_to_load}")
        utils.write_to_file("Please ensure the file exists and you have all required drivers (e.g., pyodbc).")
        sys.exit(1)
    except Exception as e:
        utils.write_to_file(f"[CRITICAL] Error loading plug-in: {e}")
        sys.exit(1)

    # --- 3. Run the Plug-in ---
    try:
        # We call the 'run_all_checks' function inside the loaded module
        # and pass it its specific config section and the utils.
        checker_module.run_all_checks(target_config, utils)
        
    except AttributeError:
        # This triggers if the plug-in doesn't have a 'run_all_checks' function
        utils.write_to_file(f"[CRITICAL] Plug-in {module_name_to_load} is invalid.")
        utils.write_to_file("It does not have a 'run_all_checks(config, utils)' function.")
        sys.exit(1)
    except Exception as e:
        utils.write_to_file(f"[CRITICAL] An error occurred while running checks: {e}")
        sys.exit(1)

    utils.write_to_file("\n--- Audit Complete ---")

# ---------- Run the Tool ----------
if __name__ == "__main__":
    main()