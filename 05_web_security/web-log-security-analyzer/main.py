#!/usr/bin/env python3

import logs_parser
import sys
import detection


def main(analyze_file):
    with open(analyze_file, 'r') as file:
        lines = file.readlines()  # Lit toutes les lignes
        tableau = logs_parser.appache_parse(lines)

        xss_attacks = []

        for entry in tableau:
            entry['jwt'] = detection.detect_jwt(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['lfi'] = detection.detect_lfi(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['sql'] = detection.detect_sql(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['xss'] = detection.detect_xss(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['cmd_inj'] = detection.detect_command_injection(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['xxe'] = detection.detect_xxe(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['ldap'] = detection.detect_ldap_injection(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['ssrf'] = detection.detect_ssrf(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['template'] = detection.detect_template_injection(
                entry['url'],
                entry['user_agent'],
                entry['referer']
            )
            entry['url'] = detection.detect_open_redirect(
                entry['url']
            )
            entry['scanner'] = detection.detect_scanner(
                entry['user_agent']
            )


if __name__ == "__main__":
    file_name = sys.argv[1]
    main(file_name)
