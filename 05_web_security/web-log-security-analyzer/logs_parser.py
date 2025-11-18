#!/usr/bin/env python3
"""Apache log parser module"""
import re

# Apache Combined Log Format regex pattern
APACHE_LOG_PATTERN = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'


def parse_apache_logs(log_lines):

    log_entries = []

    for line in log_lines:
        cleaned_line = line.strip().lstrip('"')
        match = re.match(APACHE_LOG_PATTERN, cleaned_line.strip())

        if match:
            log_entries.append({
                'ip': match.group(1),
                'datetime': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'protocol': match.group(5),
                'status': match.group(6),
                'size': match.group(7),
                'referer': match.group(8),
                'user_agent': match.group(9)
            })

    return log_entries

