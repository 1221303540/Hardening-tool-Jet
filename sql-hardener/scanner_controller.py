#!/usr/bin/env python3

import threading
import queue
import configparser
import importlib
import sys
from io import StringIO
import utils
import ai_analyzer
import database

class ScannerController:
    """
    Controller class to manage database scanning operations.
    Bridges the GUI and the scanning logic, runs scans in separate threads.
    """
    
    def __init__(self, progress_callback=None, completion_callback=None, log_callback=None):
        """
        Initialize the scanner controller.
        
        Args:
            progress_callback: Function to call with progress updates (0-100)
            completion_callback: Function to call when scan completes (results_dict)
            log_callback: Function to call with log messages (text)
        """
        self.progress_callback = progress_callback
        self.completion_callback = completion_callback
        self.log_callback = log_callback
        self.scan_thread = None
        self.is_scanning = False
        self.stop_requested = False
        
    def start_scan(self, database_type, connection_params, api_key=None):
        """
        Starts a database scan in a separate thread.
        
        Args:
            database_type: 'mssql' or 'mongodb'
            connection_params: Dictionary with connection parameters
            api_key: Optional API key for AI summary generation
        """
        if self.is_scanning:
            self.log("Scan already in progress!")
            return False
        
        self.is_scanning = True
        self.stop_requested = False
        
        # Start scan in separate thread
        self.scan_thread = threading.Thread(
            target=self._run_scan,
            args=(database_type, connection_params, api_key),
            daemon=True
        )
        self.scan_thread.start()
        return True
    
    def stop_scan(self):
        """
        Requests the current scan to stop.
        """
        self.stop_requested = True
        self.log("Stop requested...")
    
    def _run_scan(self, database_type, connection_params, api_key):
        """
        Internal method that performs the actual scan.
        Runs in a separate thread.
        """
        try:
            self.log(f"Starting {database_type.upper()} Security Scan\n")
            self.update_progress(5)
            
            # Load the appropriate checker module
            if database_type == 'mssql':
                module_name = 'checkers.check_mssql'
            elif database_type == 'mongodb':
                module_name = 'checkers.check_mongodb'
            else:
                raise ValueError(f"Unknown database type: {database_type}")
            
            self.log(f"Loading scanner module: {module_name}...")
            checker_module = importlib.import_module(module_name)
            self.update_progress(10)
            
            # Create a custom utils wrapper for logging
            utils_wrapper = self._create_utils_wrapper()
            
            # Run the checks
            self.log("Connecting to database and running security checks...\n")
            self.update_progress(20)
            
            technical_report_lines = checker_module.run_all_checks(connection_params, utils_wrapper)
            
            if self.stop_requested:
                self.log("Scan stopped by user.")
                self.is_scanning = False
                return
            
            # Check if connection failed (report would contain CRITICAL connection error)
            if technical_report_lines:
                connection_failed = False
                for line in technical_report_lines:
                    if "[CRITICAL]" in line and ("connection error" in line.lower() or "authentication error" in line.lower()):
                        connection_failed = True
                        error_message = line.replace("[CRITICAL]", "").strip()
                        break
                
                if connection_failed:
                    self.log(f"\n[ERROR] {error_message}")
                    self.log("Scan aborted due to connection failure.")
                    if self.completion_callback:
                        self.completion_callback({
                            'status': 'error',
                            'error': error_message
                        })
                    self.is_scanning = False
                    return
            
            # Check if report is empty (no checks were run)
            if not technical_report_lines or len(technical_report_lines) < 2:
                error_msg = "No scan results generated. Connection may have failed or no checks were executed."
                self.log(f"\n[ERROR] {error_msg}")
                if self.completion_callback:
                    self.completion_callback({
                        'status': 'error',
                        'error': error_msg
                    })
                self.is_scanning = False
                return
            
            self.update_progress(70)
            
            # Calculate risk metrics
            total_findings = 0
            total_crit = 0
            total_warn = 0
            risk_score = 0
            
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
            
            self.log("\n")
            self.log("RISK SUMMARY")
            self.log(f"Risk Score: {risk_score}")
            self.log(f"Total Findings: {total_findings}")
            self.log(f"Critical Issues: {total_crit}")
            self.log(f"Warnings: {total_warn}")
            self.log("")
            
            self.update_progress(80)
            
            # Generate AI summary if API key provided
            ai_summary = ""
            if api_key and technical_report_lines:
                self.log("\nEXECUTIVE SUMMARY")
                self.log("Generating summary, please wait...\n")
                
                try:
                    ai_summary = ai_analyzer.get_executive_summary(
                        technical_report_lines,
                        risk_score,
                        total_findings,
                        total_crit,
                        total_warn,
                        api_key,
                        utils_wrapper
                    )
                    self.log(ai_summary)
                except Exception as e:
                    self.log(f"[WARN] AI summary generation failed: {e}")
                    ai_summary = "AI summary could not be generated."
            
            self.update_progress(90)
            
            # Save results to database
            try:
                target_server = connection_params.get('server') or connection_params.get('connection_string', 'unknown')
                target_database = connection_params.get('database', '')
                username = connection_params.get('username', 'unknown')
                
                scan_id = database.save_scan_results(
                    database_type=database_type,
                    target_server=target_server,
                    target_database=target_database,
                    username=username,
                    risk_score=risk_score,
                    total_findings=total_findings,
                    critical_count=total_crit,
                    warning_count=total_warn,
                    ai_summary=ai_summary,
                    technical_report_lines=technical_report_lines
                )
                self.log(f"\nResults saved to database (Scan ID: {scan_id})")
            except Exception as e:
                self.log(f"[WARN] Could not save to database: {e}")
                scan_id = None
            
            self.update_progress(100)
            self.log("\nScan Complete")
            
            # Prepare results dictionary
            results = {
                'scan_id': scan_id,
                'database_type': database_type,
                'target_server': target_server,
                'target_database': target_database,
                'username': username,
                'risk_score': risk_score,
                'total_findings': total_findings,
                'critical_count': total_crit,
                'warning_count': total_warn,
                'ai_summary': ai_summary,
                'technical_report': technical_report_lines,
                'status': 'success'
            }
            
            # Call completion callback
            if self.completion_callback:
                self.completion_callback(results)
            
        except Exception as e:
            error_msg = f"[ERROR] Scan failed: {str(e)}"
            self.log(error_msg)
            
            # Call completion callback with error
            if self.completion_callback:
                self.completion_callback({
                    'status': 'error',
                    'error': str(e)
                })
        
        finally:
            self.is_scanning = False
    
    def _create_utils_wrapper(self):
        """
        Creates a wrapper object that mimics the utils module
        but redirects output to the GUI log callback.
        """
        class UtilsWrapper:
            def __init__(self, log_callback):
                self.log_callback = log_callback
            
            def write_to_file(self, text):
                if self.log_callback:
                    self.log_callback(text)
            
            def print_separator(self, char='-', length=60):
                self.write_to_file(char * length)
            
            def format_check_result(self, title, status, recommendation="", level="INFO"):
                return utils.format_check_result(title, status, recommendation, level)
        
        return UtilsWrapper(self.log_callback)
    
    def log(self, message):
        """
        Sends a log message to the GUI.
        """
        if self.log_callback:
            self.log_callback(message)
    
    def update_progress(self, percentage):
        """
        Updates the progress indicator.
        """
        if self.progress_callback:
            self.progress_callback(percentage)

def create_config_dict(database_type, **kwargs):
    """
    Creates a configuration dictionary that mimics ConfigParser section.
    
    Args:
        database_type: 'mssql' or 'mongodb'
        **kwargs: Connection parameters
        
    Returns:
        Dictionary with configuration
    """
    class ConfigDict(dict):
        """Dictionary that supports .get() like ConfigParser."""
        def get(self, key, fallback=None):
            return super().get(key, fallback)
    
    config = ConfigDict()
    
    if database_type == 'mssql':
        config.update({
            'server': kwargs.get('server', 'localhost'),
            'database': kwargs.get('database', 'master'),
            'username': kwargs.get('username', 'sa'),
            'password': kwargs.get('password', ''),
            'driver': kwargs.get('driver', '{ODBC Driver 18 for SQL Server}')
        })
    elif database_type == 'mongodb':
        config.update({
            'connection_string': kwargs.get('connection_string', 'mongodb://localhost:27017/'),
            'username': kwargs.get('username', ''),
            'password': kwargs.get('password', '')
        })
    
    return config

