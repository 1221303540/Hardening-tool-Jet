#!/usr/bin/env python3

# Risk Scoring
SCORE_CRITICAL = 10
SCORE_WARNING = 3

# Log Level Prefixes
LEVEL_CRITICAL = "CRIT"
LEVEL_WARNING = "WARN"
LEVEL_GOOD = "GOOD"
LEVEL_INFO = "INFO"

# Log Level Map
LEVEL_MAP = {
    "INFO": "[INFO]",
    "GOOD": "[GOOD]",
    "WARN": "[WARN]",
    "CRIT": "[CRIT]"
}

# Output Formatting
SEPARATOR_LENGTH = 60
SEPARATOR_CHAR = "-"
SECTION_SEPARATOR_CHAR = "="

# AI Configuration
DEFAULT_AI_TEMPERATURE = 0.25
AI_MODEL_NAME = "models/gemini-2.5-flash"

# Database System IDs - used for determining which checks to skip
DB_SYSTEM_ID_START = 4  # System databases have IDs <= 4 in MSSQL

# Connection Timeouts (in milliseconds)
MONGODB_TIMEOUT_MS = 5000

# Audit Levels for MSSQL (from registry)
AUDIT_LEVEL_NONE = 0
AUDIT_LEVEL_SUCCESS = 1
AUDIT_LEVEL_FAILED = 2
AUDIT_LEVEL_BOTH = 3

# Authentication Modes for MSSQL
AUTH_MODE_MIXED = 0
AUTH_MODE_WINDOWS_ONLY = 1

