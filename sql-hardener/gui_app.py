#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext, filedialog
import configparser
import os
from datetime import datetime
import scanner_controller
import database

class DatabaseSecurityScannerGUI:
    """
    Main GUI application for the Database Security Scanner.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Database Security Scanner")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Load configuration
        self.config = self.load_config()
        self.api_key = self.config.get('genai', 'api_key', fallback='')
        
        # Scanner controller
        self.scanner = None
        
        # Current scan data
        self.selected_db_type = None
        self.scan_results = None
        
        # Setup menu bar
        self.setup_menu()
        
        # Main container
        self.main_container = ttk.Frame(self.root, padding="10")
        self.main_container.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights for resizing
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        self.main_container.columnconfigure(0, weight=1)
        self.main_container.rowconfigure(0, weight=1)
        
        # Show initial screen
        self.show_database_selection()
    
    def load_config(self):
        """Load configuration from config.ini"""
        config = configparser.ConfigParser()
        try:
            config.read('config.ini')
        except Exception as e:
            print(f"[WARN] Could not read config.ini: {e}")
        return config
    
    def setup_menu(self):
        """Setup the menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="New Scan", command=self.show_database_selection)
        file_menu.add_command(label="View History", command=self.show_scan_history)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def clear_main_container(self):
        """Clear all widgets from main container"""
        for widget in self.main_container.winfo_children():
            widget.destroy()
    
    def show_database_selection(self):
        """Show the database type selection screen"""
        self.clear_main_container()
        self.selected_db_type = None
        
        # Title
        title_frame = ttk.Frame(self.main_container)
        title_frame.grid(row=0, column=0, pady=20)
        
        title_label = ttk.Label(
            title_frame,
            text="Database Security Scanner",
            font=("Helvetica", 24, "bold")
        )
        title_label.pack()
        
        subtitle_label = ttk.Label(
            title_frame,
            text="Select the database type you want to scan",
            font=("Helvetica", 12)
        )
        subtitle_label.pack(pady=10)
        
        # Database selection buttons
        button_frame = ttk.Frame(self.main_container)
        button_frame.grid(row=1, column=0, pady=40)
        
        # MSSQL Button
        mssql_frame = ttk.Frame(button_frame)
        mssql_frame.grid(row=0, column=0, padx=30)
        
        mssql_btn = tk.Button(
            mssql_frame,
            text="Microsoft SQL Server",
            width=25,
            height=4,
            bg="#0078D4",
            fg="white",
            font=("Helvetica", 14, "bold"),
            cursor="hand2",
            command=lambda: self.select_database('mssql')
        )
        mssql_btn.pack()
        
        mssql_desc = ttk.Label(
            mssql_frame,
            text="Scan MS SQL Server instances\nfor security vulnerabilities",
            justify=tk.CENTER
        )
        mssql_desc.pack(pady=10)
        
        # MongoDB Button
        mongodb_frame = ttk.Frame(button_frame)
        mongodb_frame.grid(row=0, column=1, padx=30)
        
        mongodb_btn = tk.Button(
            mongodb_frame,
            text="MongoDB",
            width=25,
            height=4,
            bg="#00A67E",
            fg="white",
            font=("Helvetica", 14, "bold"),
            cursor="hand2",
            command=lambda: self.select_database('mongodb')
        )
        mongodb_btn.pack()
        
        mongodb_desc = ttk.Label(
            mongodb_frame,
            text="Scan MongoDB instances\nfor security vulnerabilities",
            justify=tk.CENTER
        )
        mongodb_desc.pack(pady=10)
        
        # History button
        history_frame = ttk.Frame(self.main_container)
        history_frame.grid(row=2, column=0, pady=20)
        
        history_btn = ttk.Button(
            history_frame,
            text="View Scan History",
            command=self.show_scan_history
        )
        history_btn.pack()
    
    def select_database(self, db_type):
        """Handle database type selection"""
        self.selected_db_type = db_type
        self.show_credentials_screen()
    
    def show_credentials_screen(self):
        """Show the credentials input screen"""
        self.clear_main_container()
        
        # Title
        title_label = ttk.Label(
            self.main_container,
            text=f"{self.selected_db_type.upper()} Connection Details",
            font=("Helvetica", 18, "bold")
        )
        title_label.grid(row=0, column=0, pady=20, sticky=tk.W)
        
        # Back button
        back_btn = ttk.Button(
            self.main_container,
            text="← Back",
            command=self.show_database_selection
        )
        back_btn.grid(row=0, column=1, pady=20, sticky=tk.E)
        
        # Form frame
        form_frame = ttk.Frame(self.main_container, padding="20")
        form_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        self.credential_entries = {}
        
        row_num = 0
        
        if self.selected_db_type == 'mssql':
            # MSSQL specific fields
            fields = [
                ('Server:', 'server', self.config.get('mssql', 'server', fallback='localhost\\SQLEXPRESS')),
                ('Database:', 'database', self.config.get('mssql', 'database', fallback='master')),
                ('Username:', 'username', self.config.get('mssql', 'username', fallback='sa')),
                ('Password:', 'password', ''),
                ('Driver:', 'driver', self.config.get('mssql', 'driver', fallback='{ODBC Driver 18 for SQL Server}'))
            ]
        else:  # mongodb
            fields = [
                ('Connection String:', 'connection_string', self.config.get('mongodb', 'connection_string', fallback='mongodb://localhost:27017/')),
                ('Username:', 'username', self.config.get('mongodb', 'username', fallback='')),
                ('Password:', 'password', '')
            ]
        
        for label_text, field_name, default_value in fields:
            label = ttk.Label(form_frame, text=label_text, font=("Helvetica", 11))
            label.grid(row=row_num, column=0, sticky=tk.W, pady=8, padx=10)
            
            if 'password' in field_name.lower():
                entry = ttk.Entry(form_frame, width=50, show="*")
            else:
                entry = ttk.Entry(form_frame, width=50)
            
            entry.grid(row=row_num, column=1, sticky=(tk.W, tk.E), pady=8, padx=10)
            entry.insert(0, default_value)
            
            self.credential_entries[field_name] = entry
            row_num += 1
        
        # API Key field
        ttk.Label(form_frame, text="", font=("Helvetica", 11)).grid(row=row_num, column=0, pady=5)
        row_num += 1
        
        ttk.Label(
            form_frame,
            text="AI API Key (optional):",
            font=("Helvetica", 11)
        ).grid(row=row_num, column=0, sticky=tk.W, pady=8, padx=10)
        
        api_entry = ttk.Entry(form_frame, width=50, show="*")
        api_entry.grid(row=row_num, column=1, sticky=(tk.W, tk.E), pady=8, padx=10)
        api_entry.insert(0, self.api_key)
        self.credential_entries['api_key'] = api_entry
        row_num += 1
        
        # Info label
        info_label = ttk.Label(
            form_frame,
            text="Note: API key is required for AI-powered executive summary",
            font=("Helvetica", 9),
            foreground="gray"
        )
        info_label.grid(row=row_num, column=1, sticky=tk.W, padx=10)
        row_num += 1
        
        # Buttons
        button_frame = ttk.Frame(form_frame)
        button_frame.grid(row=row_num, column=0, columnspan=2, pady=30)
        
        start_btn = tk.Button(
            button_frame,
            text="Start Scan",
            width=20,
            height=2,
            bg="#28a745",
            fg="white",
            font=("Helvetica", 12, "bold"),
            cursor="hand2",
            command=self.start_scan
        )
        start_btn.pack(side=tk.LEFT, padx=10)
        
        cancel_btn = ttk.Button(
            button_frame,
            text="Cancel",
            command=self.show_database_selection
        )
        cancel_btn.pack(side=tk.LEFT, padx=10)
        
        # Configure column weights
        form_frame.columnconfigure(1, weight=1)
    
    def start_scan(self):
        """Start the security scan"""
        # Validate inputs
        if not self.validate_credentials():
            return
        
        # Get credentials
        connection_params = {}
        for field_name, entry in self.credential_entries.items():
            if field_name != 'api_key':
                connection_params[field_name] = entry.get()
        
        api_key = self.credential_entries['api_key'].get().strip()
        if not api_key or 'YOUR_KEY_HERE' in api_key:
            api_key = None
        
        # Show scanning screen
        self.show_scanning_screen(connection_params, api_key)
    
    def validate_credentials(self):
        """Validate credential inputs"""
        for field_name, entry in self.credential_entries.items():
            if field_name == 'api_key':
                continue
            
            value = entry.get().strip()
            
            # Check required fields
            if field_name in ['username', 'server', 'connection_string'] and not value:
                # Username and connection_string can be optional for MongoDB
                if self.selected_db_type == 'mongodb' and field_name == 'username':
                    continue
                if field_name != 'server' or self.selected_db_type != 'mssql':
                    continue
            
            if field_name == 'password':
                # Password can be empty (will be handled by checker)
                continue
        
        return True
    
    def show_scanning_screen(self, connection_params, api_key):
        """Show the scanning progress screen"""
        self.clear_main_container()
        
        # Title
        title_label = ttk.Label(
            self.main_container,
            text="Scanning in Progress...",
            font=("Helvetica", 18, "bold")
        )
        title_label.grid(row=0, column=0, pady=20)
        
        # Progress bar
        progress_frame = ttk.Frame(self.main_container)
        progress_frame.grid(row=1, column=0, pady=20, sticky=(tk.W, tk.E))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100,
            length=600
        )
        self.progress_bar.grid(row=0, column=0, padx=20, sticky=(tk.W, tk.E))
        
        self.progress_label = ttk.Label(progress_frame, text="0%")
        self.progress_label.grid(row=1, column=0, pady=5)
        
        # Log output
        log_frame = ttk.LabelFrame(self.main_container, text="Scan Log", padding="10")
        log_frame.grid(row=2, column=0, pady=20, sticky=(tk.W, tk.E, tk.N, tk.S))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure tags for colored output
        self.log_text.tag_config("CRIT", foreground="red", font=("Courier", 9, "bold"))
        self.log_text.tag_config("WARN", foreground="orange", font=("Courier", 9, "bold"))
        self.log_text.tag_config("GOOD", foreground="green", font=("Courier", 9, "bold"))
        self.log_text.tag_config("INFO", foreground="blue")
        
        # Stop button
        button_frame = ttk.Frame(self.main_container)
        button_frame.grid(row=3, column=0, pady=10)
        
        self.stop_btn = ttk.Button(
            button_frame,
            text="Stop Scan",
            command=self.stop_scan
        )
        self.stop_btn.pack()
        
        # Configure row weights
        self.main_container.rowconfigure(2, weight=1)
        
        # Start the scan
        self.scanner = scanner_controller.ScannerController(
            progress_callback=self.update_progress,
            completion_callback=self.scan_completed,
            log_callback=self.append_log
        )
        
        config_dict = scanner_controller.create_config_dict(
            self.selected_db_type,
            **connection_params
        )
        
        self.scanner.start_scan(self.selected_db_type, config_dict, api_key)
    
    def update_progress(self, percentage):
        """Update the progress bar"""
        self.progress_var.set(percentage)
        self.progress_label.config(text=f"{int(percentage)}%")
        self.root.update_idletasks()
    
    def append_log(self, message):
        """Append message to the log text widget"""
        # Detect severity and apply appropriate tag
        tag = None
        if "[CRIT]" in message:
            tag = "CRIT"
        elif "[WARN]" in message:
            tag = "WARN"
        elif "[GOOD]" in message:
            tag = "GOOD"
        elif "[INFO]" in message:
            tag = "INFO"
        
        self.log_text.insert(tk.END, message + "\n", tag)
        self.log_text.see(tk.END)
        self.root.update_idletasks()
    
    def stop_scan(self):
        """Stop the current scan"""
        if self.scanner and self.scanner.is_scanning:
            self.scanner.stop_scan()
            self.stop_btn.config(state="disabled")
    
    def scan_completed(self, results):
        """Handle scan completion"""
        self.scan_results = results
        
        if results.get('status') == 'error':
            messagebox.showerror("Scan Error", f"Scan failed: {results.get('error')}")
            self.show_database_selection()
        else:
            # Wait a moment then show results
            self.root.after(1000, self.show_results_screen)
    
    def show_results_screen(self):
        """Show the scan results screen"""
        if not self.scan_results:
            messagebox.showerror("Error", "No scan results available")
            self.show_database_selection()
            return
        
        self.clear_main_container()
        
        # Title bar with info
        title_frame = ttk.Frame(self.main_container)
        title_frame.grid(row=0, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        title_frame.columnconfigure(1, weight=1)
        
        title_label = ttk.Label(
            title_frame,
            text="Scan Results",
            font=("Helvetica", 18, "bold")
        )
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # Scan info
        info_text = f"{self.scan_results['database_type'].upper()} - {self.scan_results['target_server']}"
        info_label = ttk.Label(title_frame, text=info_text, font=("Helvetica", 10))
        info_label.grid(row=0, column=1, padx=20)
        
        # Button frame for actions
        button_frame = ttk.Frame(title_frame)
        button_frame.grid(row=0, column=2, sticky=tk.E)
        
        export_btn = ttk.Button(
            button_frame,
            text="Export Report",
            command=self.export_report
        )
        export_btn.pack(side=tk.LEFT, padx=5)
        
        new_scan_btn = ttk.Button(
            button_frame,
            text="New Scan",
            command=self.show_database_selection
        )
        new_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # Risk score panel
        risk_frame = ttk.LabelFrame(self.main_container, text="Risk Assessment", padding="10")
        risk_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        
        # Determine risk level color
        risk_score = self.scan_results['risk_score']
        if risk_score >= 50:
            risk_color = "red"
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_color = "orange"
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_color = "yellow"
            risk_level = "MEDIUM"
        else:
            risk_color = "green"
            risk_level = "LOW"
        
        # Risk metrics in columns
        metrics_frame = ttk.Frame(risk_frame)
        metrics_frame.pack(fill=tk.X)
        
        # Risk Score
        score_frame = ttk.Frame(metrics_frame)
        score_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        score_label = tk.Label(
            score_frame,
            text=str(risk_score),
            font=("Helvetica", 36, "bold"),
            fg=risk_color
        )
        score_label.pack()
        
        ttk.Label(score_frame, text="Risk Score", font=("Helvetica", 10)).pack()
        ttk.Label(score_frame, text=f"({risk_level})", font=("Helvetica", 9), foreground=risk_color).pack()
        
        # Separator
        ttk.Separator(metrics_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)
        
        # Findings breakdown
        findings_frame = ttk.Frame(metrics_frame)
        findings_frame.pack(side=tk.LEFT, padx=20, pady=10)
        
        ttk.Label(
            findings_frame,
            text=str(self.scan_results['total_findings']),
            font=("Helvetica", 24, "bold")
        ).grid(row=0, column=0, rowspan=2)
        
        ttk.Label(findings_frame, text="Total Findings", font=("Helvetica", 10)).grid(row=0, column=1, sticky=tk.W, padx=10)
        
        findings_detail = f"Critical: {self.scan_results['critical_count']} | Warnings: {self.scan_results['warning_count']}"
        ttk.Label(findings_frame, text=findings_detail, font=("Helvetica", 9)).grid(row=1, column=1, sticky=tk.W, padx=10)
        
        # Tabbed interface for detailed results
        notebook = ttk.Notebook(self.main_container)
        notebook.grid(row=2, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Tab 1: Executive Summary (AI)
        summary_frame = ttk.Frame(notebook, padding="10")
        notebook.add(summary_frame, text="Executive Summary")
        
        summary_text = scrolledtext.ScrolledText(
            summary_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Helvetica", 11)
        )
        summary_text.pack(fill=tk.BOTH, expand=True)
        
        ai_summary = self.scan_results.get('ai_summary', 'No AI summary available')
        summary_text.insert(tk.END, ai_summary)
        summary_text.config(state=tk.DISABLED)
        
        # Tab 2: Detailed Findings
        findings_frame = ttk.Frame(notebook, padding="10")
        notebook.add(findings_frame, text="Detailed Findings")
        
        # Create treeview for findings
        tree_frame = ttk.Frame(findings_frame)
        tree_frame.pack(fill=tk.BOTH, expand=True)
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Treeview
        self.findings_tree = ttk.Treeview(
            tree_frame,
            columns=("severity", "check", "status", "recommendation"),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.findings_tree.yview)
        tree_scroll_x.config(command=self.findings_tree.xview)
        
        # Define columns
        self.findings_tree.heading("severity", text="Severity")
        self.findings_tree.heading("check", text="Check Name")
        self.findings_tree.heading("status", text="Status")
        self.findings_tree.heading("recommendation", text="Recommendation")
        
        self.findings_tree.column("severity", width=100, anchor=tk.CENTER)
        self.findings_tree.column("check", width=250)
        self.findings_tree.column("status", width=200)
        self.findings_tree.column("recommendation", width=400)
        
        self.findings_tree.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colored rows
        self.findings_tree.tag_configure("CRITICAL", background="#ffcccc")
        self.findings_tree.tag_configure("WARNING", background="#fff4cc")
        self.findings_tree.tag_configure("GOOD", background="#ccffcc")
        self.findings_tree.tag_configure("INFO", background="#e6f3ff")
        
        # Populate findings
        self.populate_findings_tree()
        
        # Tab 3: Technical Report (Raw)
        technical_frame = ttk.Frame(notebook, padding="10")
        notebook.add(technical_frame, text="Technical Report")
        
        technical_text = scrolledtext.ScrolledText(
            technical_frame,
            wrap=tk.WORD,
            width=80,
            height=20,
            font=("Courier", 9)
        )
        technical_text.pack(fill=tk.BOTH, expand=True)
        
        # Configure tags for colored output
        technical_text.tag_config("CRIT", foreground="red", font=("Courier", 9, "bold"))
        technical_text.tag_config("WARN", foreground="orange", font=("Courier", 9, "bold"))
        technical_text.tag_config("GOOD", foreground="green", font=("Courier", 9, "bold"))
        technical_text.tag_config("INFO", foreground="blue")
        
        for line in self.scan_results.get('technical_report', []):
            tag = None
            if "[CRIT]" in line:
                tag = "CRIT"
            elif "[WARN]" in line:
                tag = "WARN"
            elif "[GOOD]" in line:
                tag = "GOOD"
            elif "[INFO]" in line:
                tag = "INFO"
            
            technical_text.insert(tk.END, line + "\n", tag)
        
        technical_text.config(state=tk.DISABLED)
        
        # Configure row weights for resizing
        self.main_container.rowconfigure(2, weight=1)
        self.main_container.columnconfigure(0, weight=1)
    
    def populate_findings_tree(self):
        """Populate the findings treeview with scan results"""
        if not self.scan_results or 'technical_report' not in self.scan_results:
            return
        
        # Parse findings from technical report
        findings = self.parse_findings_for_tree(self.scan_results['technical_report'])
        
        for finding in findings:
            severity = finding['severity']
            check_name = finding['check_name']
            status = finding['status']
            recommendation = finding['recommendation']
            
            self.findings_tree.insert(
                "",
                tk.END,
                values=(severity, check_name, status, recommendation),
                tags=(severity,)
            )
    
    def parse_findings_for_tree(self, report_lines):
        """Parse technical report lines into structured findings for tree view"""
        findings = []
        current_finding = None
        
        for line in report_lines:
            line = line.strip()
            
            # Skip separators and section headers
            if line.startswith("---") or not line or line.startswith("==="):
                continue
            
            # Parse findings with severity tags
            if line.startswith("[CRIT]"):
                severity = "CRITICAL"
                parts = line[6:].split(":", 1)
            elif line.startswith("[WARN]"):
                severity = "WARNING"
                parts = line[6:].split(":", 1)
            elif line.startswith("[GOOD]"):
                severity = "GOOD"
                parts = line[6:].split(":", 1)
            elif line.startswith("[INFO]"):
                severity = "INFO"
                parts = line[6:].split(":", 1)
            else:
                # Check for recommendations
                if current_finding and ("└──" in line or "Recommendation:" in line):
                    rec_text = line.replace("└──", "").replace("Recommendation:", "").strip()
                    current_finding['recommendation'] = rec_text
                continue
            
            if len(parts) == 2:
                check_name = parts[0].strip()
                status = parts[1].strip()
                
                finding = {
                    'severity': severity,
                    'check_name': check_name,
                    'status': status,
                    'recommendation': ''
                }
                findings.append(finding)
                current_finding = finding
        
        return findings
    
    def export_report(self):
        """Export scan report to text file"""
        if not self.scan_results:
            return
        
        # Ask for save location
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile=f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("="*80 + "\n")
                f.write("DATABASE SECURITY SCAN REPORT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Database Type: {self.scan_results['database_type'].upper()}\n")
                f.write(f"Target Server: {self.scan_results['target_server']}\n")
                f.write(f"Target Database: {self.scan_results.get('target_database', 'N/A')}\n")
                f.write(f"Scan ID: {self.scan_results.get('scan_id', 'N/A')}\n")
                f.write(f"Username: {self.scan_results['username']}\n\n")
                
                f.write("="*80 + "\n")
                f.write("RISK ASSESSMENT\n")
                f.write("="*80 + "\n\n")
                
                f.write(f"Risk Score: {self.scan_results['risk_score']}\n")
                f.write(f"Total Findings: {self.scan_results['total_findings']}\n")
                f.write(f"Critical: {self.scan_results['critical_count']}\n")
                f.write(f"Warnings: {self.scan_results['warning_count']}\n\n")
                
                f.write("="*80 + "\n")
                f.write("EXECUTIVE SUMMARY\n")
                f.write("="*80 + "\n\n")
                
                f.write(self.scan_results.get('ai_summary', 'No AI summary available'))
                f.write("\n\n")
                
                f.write("="*80 + "\n")
                f.write("TECHNICAL REPORT\n")
                f.write("="*80 + "\n\n")
                
                for line in self.scan_results.get('technical_report', []):
                    f.write(line + "\n")
            
            messagebox.showinfo("Export Successful", f"Report exported to:\n{filename}")
        
        except Exception as e:
            messagebox.showerror("Export Failed", f"Could not export report:\n{str(e)}")
    
    def show_scan_history(self):
        """Show scan history screen"""
        self.clear_main_container()
        
        # Title
        title_frame = ttk.Frame(self.main_container)
        title_frame.grid(row=0, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E))
        
        title_label = ttk.Label(
            title_frame,
            text="Scan History",
            font=("Helvetica", 18, "bold")
        )
        title_label.grid(row=0, column=0, sticky=tk.W)
        
        # Buttons
        button_frame = ttk.Frame(title_frame)
        button_frame.grid(row=0, column=1, sticky=tk.E)
        
        refresh_btn = ttk.Button(
            button_frame,
            text="Refresh",
            command=self.show_scan_history
        )
        refresh_btn.pack(side=tk.LEFT, padx=5)
        
        new_scan_btn = ttk.Button(
            button_frame,
            text="New Scan",
            command=self.show_database_selection
        )
        new_scan_btn.pack(side=tk.LEFT, padx=5)
        
        # History list
        history_frame = ttk.LabelFrame(self.main_container, text="Previous Scans", padding="10")
        history_frame.grid(row=1, column=0, columnspan=2, pady=10, sticky=(tk.W, tk.E, tk.N, tk.S))
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Create treeview for history
        tree_frame = ttk.Frame(history_frame)
        tree_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)
        
        # Scrollbars
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL)
        tree_scroll_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL)
        tree_scroll_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Treeview
        self.history_tree = ttk.Treeview(
            tree_frame,
            columns=("scan_id", "timestamp", "db_type", "server", "risk_score", "findings", "status"),
            show="headings",
            yscrollcommand=tree_scroll_y.set,
            xscrollcommand=tree_scroll_x.set
        )
        
        tree_scroll_y.config(command=self.history_tree.yview)
        tree_scroll_x.config(command=self.history_tree.xview)
        
        # Define columns
        self.history_tree.heading("scan_id", text="ID")
        self.history_tree.heading("timestamp", text="Timestamp")
        self.history_tree.heading("db_type", text="Database")
        self.history_tree.heading("server", text="Server")
        self.history_tree.heading("risk_score", text="Risk Score")
        self.history_tree.heading("findings", text="Findings")
        self.history_tree.heading("status", text="Status")
        
        self.history_tree.column("scan_id", width=50, anchor=tk.CENTER)
        self.history_tree.column("timestamp", width=150)
        self.history_tree.column("db_type", width=100)
        self.history_tree.column("server", width=200)
        self.history_tree.column("risk_score", width=100, anchor=tk.CENTER)
        self.history_tree.column("findings", width=150)
        self.history_tree.column("status", width=100, anchor=tk.CENTER)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure row colors based on risk
        self.history_tree.tag_configure("critical", background="#ffcccc")
        self.history_tree.tag_configure("high", background="#fff4cc")
        self.history_tree.tag_configure("medium", background="#ffffcc")
        self.history_tree.tag_configure("low", background="#ccffcc")
        
        # Bind double-click to view details
        self.history_tree.bind("<Double-Button-1>", self.view_history_item)
        
        # Load history
        self.load_scan_history()
        
        # Action buttons
        action_frame = ttk.Frame(history_frame)
        action_frame.grid(row=1, column=0, pady=10)
        
        view_btn = ttk.Button(
            action_frame,
            text="View Details",
            command=lambda: self.view_history_item(None)
        )
        view_btn.pack(side=tk.LEFT, padx=5)
        
        delete_btn = ttk.Button(
            action_frame,
            text="Delete Selected",
            command=self.delete_history_item
        )
        delete_btn.pack(side=tk.LEFT, padx=5)
        
        # Info label
        info_label = ttk.Label(
            history_frame,
            text="Double-click a scan to view details",
            font=("Helvetica", 9),
            foreground="gray"
        )
        info_label.grid(row=2, column=0, pady=5)
        
        # Configure row weights
        self.main_container.rowconfigure(1, weight=1)
        self.main_container.columnconfigure(0, weight=1)
    
    def load_scan_history(self):
        """Load scan history from database"""
        # Clear existing items
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        # Get history from database
        try:
            scans = database.get_scan_history(limit=100)
            
            if not scans:
                # Insert a placeholder message
                self.history_tree.insert(
                    "",
                    tk.END,
                    values=("", "No scans found", "", "", "", "", "")
                )
                return
            
            for scan in scans:
                scan_id = scan['scan_id']
                timestamp = scan['timestamp']
                db_type = scan['database_type'].upper()
                server = scan['target_server']
                risk_score = scan['risk_score']
                findings = f"C:{scan['critical_count']} W:{scan['warning_count']}"
                status = scan['status'].upper()
                
                # Determine row tag based on risk score
                if risk_score >= 50:
                    tag = "critical"
                elif risk_score >= 30:
                    tag = "high"
                elif risk_score >= 10:
                    tag = "medium"
                else:
                    tag = "low"
                
                self.history_tree.insert(
                    "",
                    tk.END,
                    values=(scan_id, timestamp, db_type, server, risk_score, findings, status),
                    tags=(tag,)
                )
        
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not load scan history:\n{str(e)}")
    
    def view_history_item(self, event):
        """View details of a selected history item"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan to view")
            return
        
        # Get scan ID from selected item
        item = self.history_tree.item(selection[0])
        values = item['values']
        
        if not values or values[0] == '':
            return
        
        scan_id = values[0]
        
        # Load scan details from database
        try:
            scan_data = database.get_scan_details(scan_id)
            
            if not scan_data:
                messagebox.showerror("Error", f"Could not find scan with ID {scan_id}")
                return
            
            # Convert to results format and display
            self.scan_results = {
                'scan_id': scan_data['scan_id'],
                'database_type': scan_data['database_type'],
                'target_server': scan_data['target_server'],
                'target_database': scan_data['target_database'],
                'username': scan_data['username'],
                'risk_score': scan_data['risk_score'],
                'total_findings': scan_data['total_findings'],
                'critical_count': scan_data['critical_count'],
                'warning_count': scan_data['warning_count'],
                'ai_summary': scan_data['ai_summary'] or 'No AI summary available',
                'technical_report': [f['finding_text'] for f in scan_data['findings']],
                'status': 'success'
            }
            
            self.show_results_screen()
        
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not load scan details:\n{str(e)}")
    
    def delete_history_item(self):
        """Delete a selected history item"""
        selection = self.history_tree.selection()
        if not selection:
            messagebox.showwarning("No Selection", "Please select a scan to delete")
            return
        
        # Get scan ID from selected item
        item = self.history_tree.item(selection[0])
        values = item['values']
        
        if not values or values[0] == '':
            return
        
        scan_id = values[0]
        
        # Confirm deletion
        if not messagebox.askyesno("Confirm Delete", f"Are you sure you want to delete scan #{scan_id}?"):
            return
        
        # Delete from database
        try:
            database.delete_scan(scan_id)
            messagebox.showinfo("Success", "Scan deleted successfully")
            self.load_scan_history()
        
        except Exception as e:
            messagebox.showerror("Database Error", f"Could not delete scan:\n{str(e)}")
    
    def show_about(self):
        """Show about dialog"""
        messagebox.showinfo(
            "About",
            "Database Security Scanner v1.0\n\n"
            "A comprehensive security auditing tool for\n"
            "MS SQL Server and MongoDB databases.\n\n"
            "Powered by AI for intelligent threat analysis."
        )

def main():
    """Main entry point"""
    root = tk.Tk()
    app = DatabaseSecurityScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

