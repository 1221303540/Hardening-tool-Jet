#!/usr/bin/env python3

import sys
import configparser
import importlib

# Import the helper functions and the new AI module
import utils 
import ai_analyzer

def main():
    """
    Main "engine" for the compliance tool.
    Reads config.ini, loads the plug-in, runs checks,
    calls GenAI, and prints the final report.
    """
    utils.write_to_file("--- Database Security & Compliance Auditor ---")
    
    # --- 1. Read Configuration ---
    config = configparser.ConfigParser()
    api_key = None
    technical_report_lines = []
    
    try:
        config.read('config.ini')
        target_db_name = config.get('main', 'target_db')
        target_config = config[target_db_name]
        
        # Get the AI API Key
        api_key = config.get('genai', 'api_key', fallback=None)
        if not api_key or "AIzaSyAoSScfz1pS6nm2Dki7bsRB-UVTj2vNfso" in api_key:
            utils.write_to_file("\n[WARN] GenAI API key not found in config.ini. Skipping AI summary.\n")
            api_key = None

    except Exception as e:
        utils.write_to_file(f"[CRITICAL] Error reading config.ini: {e}")
        sys.exit(1)

    # --- 2. Dynamically Load the Plug-in ---
    try:
        module_name_to_load = target_config.get('module_name')
        utils.write_to_file(f"Loading plug-in: {module_name_to_load}...")
        checker_module = importlib.import_module(module_name_to_load)
        
    except Exception as e:
        utils.write_to_file(f"[CRITICAL] Error loading plug-in: {e}")
        sys.exit(1)

    # --- 3. Run the Plug-in ---
    try:
        # The plug-in runs and returns the full list of findings
        technical_report_lines = checker_module.run_all_checks(target_config, utils)
        
    except Exception as e:
        utils.write_to_file(f"[CRITICAL] An error occurred while running checks: {e}")
        sys.exit(1)

    # --- 4. Print the Full Technical Report ---
    utils.write_to_file("\n### Detailed Technical Report ###")
    for line in technical_report_lines:
        utils.write_to_file(line)

    # --- 5. Generate AI Summary (if key exists) ---
    if api_key and technical_report_lines:
        utils.print_separator("=", 60)
        utils.write_to_file("### AI-Powered Executive Summary ###")
        utils.write_to_file("... (Generating summary, please wait) ...")
        
        summary = ai_analyzer.get_executive_summary(technical_report_lines, api_key, utils)
        
        utils.write_to_file("\n" + summary)
        utils.print_separator("=", 60)

    utils.write_to_file("\n--- Audit Complete ---")

# ---------- Run the Tool ----------
if __name__ == "__main__":
    main()