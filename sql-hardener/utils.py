#!/usr/bin/env python3

def write_to_file(text):
    """Writes text to both console and file."""
    print(text)
    # Note: File writing logic remains commented out for simplicity
    # with open(output_file, 'a', encoding='utf-8') as f:
    #     f.write(text + '\n')

def print_separator(char='-', length=60):
    """Prints a separator line."""
    write_to_file(char * length)

def print_check_result(title, status, recommendation="", level="INFO"):
    """Formats and prints the result of a check."""
    level_map = {
        "INFO": "[INFO]",
        "GOOD": "[GOOD]",
        "WARN": "[WARN]",
        "CRIT": "[CRIT]"
    }
    prefix = level_map.get(level, "[INFO]")
    write_to_file(f"{prefix} {title}: {status}")
    if recommendation:
        write_to_file(f"      └── Recommendation: {recommendation}")