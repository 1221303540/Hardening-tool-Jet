#!/usr/bin/env python3
import os
from constants import SEPARATOR_LENGTH, LEVEL_MAP

def write_to_file(text: str) -> None:
    print(text)

def print_separator(char: str = '-', length: int = SEPARATOR_LENGTH) -> None:
    write_to_file(char * length)

def format_check_result(title: str, status: str, recommendation: str = "", level: str = "INFO") -> str:
    prefix = LEVEL_MAP.get(level, "[INFO]")
    
    result_lines = []
    result_lines.append(f"{prefix} {title}: {status}")
    if recommendation:
        result_lines.append(f" 	└── Recommendation: {recommendation}")
    
    return "\n".join(result_lines)
    