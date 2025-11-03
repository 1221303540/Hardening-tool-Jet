#!/usr/bin/env python3

import sys
import os
import configparser
import importlib
import utils 
import ai_analyzer

def main():
    
    utils.write_to_file("--- Database Security & Compliance Auditor ---")
    
    # --- 1. Read Configuration ---
    config = configparser.ConfigParser()
    api_key = None
    technical_report_lines = []
    
    try:
        config.read('config.ini')
        target_db_name = config.get('main', 'target_db')
        target_config = config[target_db_name]
        
        api_key = config.get('genai', 'api_key', fallback=None)
        if not api_key or "YOUR_KEY_HERE" in api_key:
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
        technical_report_lines = checker_module.run_all_checks(target_config, utils)
        
    except Exception as e:
        utils.write_to_file(f"[CRITICAL] An error occurred while running checks: {e}")
        sys.exit(1)

    # --- 4. NEW: Calculate Risk Score & Totals ---
    total_findings = 0
    total_crit = 0
    total_warn = 0
    risk_score = 0
    
    # Define your scoring model
    SCORE_CRITICAL = 10
    SCORE_WARNING = 3

    if technical_report_lines:
        for line in technical_report_lines:
            if line.strip().startswith("[CRIT]"):
                total_crit += 1
                risk_score += SCORE_CRITICAL
            elif line.strip().startswith("[WARN]"):
                total_warn += 1
                risk_score += SCORE_WARNING
        
        total_findings = total_crit + total_warn

    # --- 5. Print the Quantitative Report ---
    # (This entire block is new)
    utils.print_separator("=", 60)
    utils.write_to_file("###  Quantitative Risk Analysis ###")
    utils.write_to_file(f"Total Risk Score: {risk_score}  (CRIT={SCORE_CRITICAL}pts, WARN={SCORE_WARNING}pts)")
    utils.write_to_file(f"Total Findings to Settle: {total_findings} (Critical: {total_crit}, Warning: {total_warn})")
    utils.print_separator("=", 60)
    
    # --- 6. Generate AI Summary (if key exists) ---
    if api_key and technical_report_lines:
        utils.write_to_file("\n###  AI-Powered Executive Summary ###") # Updated title
        utils.write_to_file("... (Generating summary, please wait) ...")
        
        # --- MODIFIED: Pass new scores to the AI ---
        summary = ai_analyzer.get_executive_summary(
            technical_report_lines,
            risk_score,
            total_findings,
            total_crit,
            total_warn,
            api_key, 
            utils
        )
        
        utils.write_to_file("\n" + summary)
        utils.print_separator("=", 60)

    # --- 7. Print the Full Technical Report ---
    utils.write_to_file("\n### Detailed Technical Report ###") # Updated title
    if not technical_report_lines:
        utils.write_to_file("All checks passed. No findings to report.")
        
    for line in technical_report_lines:
        utils.write_to_file(line)

    utils.write_to_file("\n--- Audit Complete ---")

# ---------- Run the Tool ----------
if __name__ == "__main__":
    main()