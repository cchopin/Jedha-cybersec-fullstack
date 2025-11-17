#!/usr/bin/env python3
import re


def appache_parse(lines):
    pattern = r'(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (\S+) (\S+)" (\d+) (\d+) "([^"]*)" "([^"]*)"'
    tableau = []

    for line in lines:
        clean_line = line.strip().lstrip('"')
        match = re.match(pattern, clean_line.strip())
        if match:
            tableau.append({
                'ip': match.group(1),
                'date': match.group(2),
                'method': match.group(3),
                'url': match.group(4),
                'protocol': match.group(5),
                'status': match.group(6),
                'size': match.group(7),
                'referer': match.group(8),
                'user_agent': match.group(9)
            })
    return tableau

