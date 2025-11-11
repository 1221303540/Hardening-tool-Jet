#!/usr/bin/env python3

import sqlite3
import json
from datetime import datetime
import os

DB_FILE = "scan_results.db"

def init_database():
    """
    Initializes the SQLite database and creates tables if they don't exist.
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Create scans table for metadata
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            scan_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_timestamp TEXT NOT NULL,
            database_type TEXT NOT NULL,
            target_server TEXT NOT NULL,
            target_database TEXT,
            username TEXT NOT NULL,
            risk_score INTEGER NOT NULL,
            total_findings INTEGER NOT NULL,
            critical_count INTEGER NOT NULL,
            warning_count INTEGER NOT NULL,
            ai_summary TEXT,
            scan_status TEXT DEFAULT 'completed'
        )
    """)
    
    # Create scan_findings table for detailed findings
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_findings (
            finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            check_name TEXT NOT NULL,
            severity TEXT NOT NULL,
            status TEXT NOT NULL,
            recommendation TEXT,
            finding_text TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans (scan_id)
        )
    """)
    
    conn.commit()
    conn.close()
    print(f"[INFO] Database initialized: {DB_FILE}")

def save_scan_results(database_type, target_server, target_database, username, 
                     risk_score, total_findings, critical_count, warning_count,
                     ai_summary, technical_report_lines):
    """
    Saves scan results to the database.
    
    Args:
        database_type: 'mssql' or 'mongodb'
        target_server: Server address/connection string
        target_database: Database name (if applicable)
        username: Username used for connection
        risk_score: Calculated risk score
        total_findings: Total number of findings
        critical_count: Number of critical findings
        warning_count: Number of warning findings
        ai_summary: AI-generated executive summary
        technical_report_lines: List of technical finding lines
        
    Returns:
        scan_id: The ID of the saved scan
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Insert scan metadata
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cursor.execute("""
        INSERT INTO scans (scan_timestamp, database_type, target_server, target_database,
                          username, risk_score, total_findings, critical_count, 
                          warning_count, ai_summary, scan_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (timestamp, database_type, target_server, target_database, username,
          risk_score, total_findings, critical_count, warning_count, 
          ai_summary, 'completed'))
    
    scan_id = cursor.lastrowid
    
    # Parse and insert findings
    findings = parse_technical_report(technical_report_lines)
    for finding in findings:
        cursor.execute("""
            INSERT INTO scan_findings (scan_id, check_name, severity, status, 
                                      recommendation, finding_text)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (scan_id, finding['check_name'], finding['severity'], 
              finding['status'], finding['recommendation'], finding['finding_text']))
    
    conn.commit()
    conn.close()
    
    print(f"[INFO] Scan results saved with ID: {scan_id}")
    return scan_id

def parse_technical_report(report_lines):
    """
    Parses the technical report lines into structured findings.
    
    Args:
        report_lines: List of report lines from the scanner
        
    Returns:
        List of finding dictionaries
    """
    findings = []
    current_check = None
    
    for line in report_lines:
        line = line.strip()
        
        # Skip separators and section headers
        if line.startswith("---") or not line:
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
            # Check for recommendations (indented lines)
            if current_check and line.startswith("└──"):
                rec_text = line.replace("└──", "").replace("Recommendation:", "").strip()
                current_check['recommendation'] = rec_text
            continue
        
        if len(parts) == 2:
            check_name = parts[0].strip()
            status = parts[1].strip()
            
            finding = {
                'check_name': check_name,
                'severity': severity,
                'status': status,
                'recommendation': '',
                'finding_text': line
            }
            findings.append(finding)
            current_check = finding
    
    return findings

def get_scan_history(limit=50):
    """
    Retrieves scan history from the database.
    
    Args:
        limit: Maximum number of scans to retrieve
        
    Returns:
        List of scan dictionaries
    """
    if not os.path.exists(DB_FILE):
        return []
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT scan_id, scan_timestamp, database_type, target_server, target_database,
               username, risk_score, total_findings, critical_count, warning_count,
               scan_status
        FROM scans
        ORDER BY scan_timestamp DESC
        LIMIT ?
    """, (limit,))
    
    rows = cursor.fetchall()
    conn.close()
    
    scans = []
    for row in rows:
        scans.append({
            'scan_id': row[0],
            'timestamp': row[1],
            'database_type': row[2],
            'target_server': row[3],
            'target_database': row[4],
            'username': row[5],
            'risk_score': row[6],
            'total_findings': row[7],
            'critical_count': row[8],
            'warning_count': row[9],
            'status': row[10]
        })
    
    return scans

def get_scan_details(scan_id):
    """
    Retrieves full details of a specific scan.
    
    Args:
        scan_id: ID of the scan to retrieve
        
    Returns:
        Dictionary with scan metadata and findings
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Get scan metadata
    cursor.execute("""
        SELECT scan_id, scan_timestamp, database_type, target_server, target_database,
               username, risk_score, total_findings, critical_count, warning_count,
               ai_summary, scan_status
        FROM scans
        WHERE scan_id = ?
    """, (scan_id,))
    
    row = cursor.fetchone()
    if not row:
        conn.close()
        return None
    
    scan_data = {
        'scan_id': row[0],
        'timestamp': row[1],
        'database_type': row[2],
        'target_server': row[3],
        'target_database': row[4],
        'username': row[5],
        'risk_score': row[6],
        'total_findings': row[7],
        'critical_count': row[8],
        'warning_count': row[9],
        'ai_summary': row[10],
        'status': row[11]
    }
    
    # Get findings
    cursor.execute("""
        SELECT check_name, severity, status, recommendation, finding_text
        FROM scan_findings
        WHERE scan_id = ?
        ORDER BY 
            CASE severity 
                WHEN 'CRITICAL' THEN 1 
                WHEN 'WARNING' THEN 2 
                WHEN 'INFO' THEN 3 
                WHEN 'GOOD' THEN 4 
            END
    """, (scan_id,))
    
    findings = []
    for row in cursor.fetchall():
        findings.append({
            'check_name': row[0],
            'severity': row[1],
            'status': row[2],
            'recommendation': row[3],
            'finding_text': row[4]
        })
    
    scan_data['findings'] = findings
    conn.close()
    
    return scan_data

def delete_scan(scan_id):
    """
    Deletes a scan and its findings from the database.
    
    Args:
        scan_id: ID of the scan to delete
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute("DELETE FROM scan_findings WHERE scan_id = ?", (scan_id,))
    cursor.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
    
    conn.commit()
    conn.close()
    
    print(f"[INFO] Scan {scan_id} deleted")

# Initialize database on module import
if __name__ != "__main__":
    try:
        init_database()
    except Exception as e:
        print(f"[WARN] Could not initialize database: {e}")

