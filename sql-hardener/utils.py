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

# ... (write_to_file and print_separator stay the same) ...

def format_check_result(title, status, recommendation="", level="INFO"):
    #Formats and returns the result of a check as a string.
    level_map = {
        "INFO": "[INFO]",
        "GOOD": "[GOOD]",
        "WARN": "[WARN]",
        "CRIT": "[CRIT]"
    }
    prefix = level_map.get(level, "[INFO]")
    
    result_lines = []
    result_lines.append(f"{prefix} {title}: {status}")
    if recommendation:
        result_lines.append(f" 	└── Recommendation: {recommendation}")
    
    return "\n".join(result_lines)