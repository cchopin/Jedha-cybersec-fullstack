#!/usr/bin/env python3
"""Attack detection module for web security log analysis"""

import re
import base64
from urllib.parse import unquote


def decode_and_combine_fields(*fields):
    decoded_fields = [unquote(field) for field in fields]
    return " ".join(decoded_fields).lower()


def detect_jwt(url, user_agent, referer):
    search_text = decode_and_combine_fields(url, user_agent, referer)

    # Simple JWT attack patterns detection
    jwt_attack_patterns = [
        r'"alg"\s*:\s*"none"',  # Algorithm None
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.',  # JWT without signature
    ]

    for pattern in jwt_attack_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True

    return False


def detect_lfi(url, user_agent, referer):
    search_text = decode_and_combine_fields(url, user_agent, referer)

    # Patterns Path Traversal / LFI / RFI
    traversal_patterns = [
        r"\.\./",  # ../
        r"\.\./\.\./",  # ../../
        r"\.\./\.\./\.\./",  # ../../../
        r"\.\.\\/",  # ..\  (Windows)
        r"\.\.\\\.\.\\/",  # ..\..\  (Windows)
        r"%2e%2e/",  # ../ encodé
        r"%2e%2e%2f",  # ../ doublement encodé
        r"\.\.%2f",  # ..%2f
        r"%252e%252e%252f",  # ../ triple encodé
        r"/etc/passwd",  # Fichier Linux classique
        r"/etc/shadow",  # Fichier passwords Linux
        r"c:\\windows",  # Chemin Windows
        r"c:/windows",  # Chemin Windows (slash)
        r"/proc/self/environ",  # Variables d'environnement Linux
        r"/var/log",  # Logs système
        r"php://filter",  # PHP wrapper
        r"php://input",  # PHP input stream
        r"file://",  # File protocol
        r"expect://",  # Expect wrapper
        r"data://",  # Data wrapper
        r"zip://",  # ZIP wrapper
        r"phar://",  # PHAR wrapper
        r"glob://",  # Glob wrapper
        r"\.\.\\",  # ..\ (Windows escaped)
        r"boot\.ini",  # Fichier Windows
        r"win\.ini",  # Fichier Windows
        r"/usr/bin",  # Binaires système
        r"/bin/bash",  # Shell
        r"/bin/sh",  # Shell
        r"\.htaccess",  # Fichier Apache
        r"\.htpasswd",  # Passwords Apache
        r"wp-config\.php",  # Config WordPress
        r"config\.php",  # Config générique
        r"\.env",  # Variables d'environnement
        r"\.git/",  # Git repository
        r"\.ssh/",  # SSH keys
        r"id_rsa",  # Clé SSH privée
    ]

    # Check each pattern
    for pattern in traversal_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True

    return False


def detect_sql(url, user_agent, referer):
    search_text = decode_and_combine_fields(url, user_agent, referer)

    # Patterns SQL injection courants
    sql_patterns = [
        r"'\s*or\s*'",  # ' OR '1'='1
        r"'\s*or\s*1\s*=\s*1",  # ' OR 1=1
        r"--",  # Commentaire SQL
        r"#",  # Commentaire MySQL
        r"/\*",  # Commentaire multi-ligne
        r"\bunion\b.*\bselect\b",  # UNION SELECT
        r"\bselect\b.*\bfrom\b",  # SELECT ... FROM
        r"\binsert\b.*\binto\b",  # INSERT INTO
        r"\bupdate\b.*\bset\b",  # UPDATE ... SET
        r"\bdelete\b.*\bfrom\b",  # DELETE FROM
        r"\bdrop\b.*\btable\b",  # DROP TABLE
        r"\bdrop\b.*\bdatabase\b",  # DROP DATABASE
        r";\s*drop\b",  # ; DROP
        r";\s*delete\b",  # ; DELETE
        r"\bexec\b\s*\(",  # EXEC(
        r"\bexecute\b\s*\(",  # EXECUTE(
        r"'\s*\+\s*'",  # Concaténation ' + '
        r"\|\|",  # Concaténation Oracle/PostgreSQL ||
        r"0x[0-9a-f]+",  # Encodage hexadécimal
        r"char\s*\(",  # CHAR() function
        r"concat\s*\(",  # CONCAT() function
        r"waitfor\s+delay",  # SQL Server time-based
        r"sleep\s*\(",  # MySQL SLEEP()
        r"benchmark\s*\(",  # MySQL BENCHMARK()
        r"pg_sleep",  # PostgreSQL sleep
        r"'\s*and\s*'",  # ' AND '1'='1
        r"'\s*and\s*1\s*=\s*1",  # ' AND 1=1
        r"admin'\s*--",  # admin'--
        r"'\s*or\s*''='",  # ' OR ''='
        r"'\s*or\s*1\s*--",  # ' OR 1--
        r"\bload_file\s*\(",  # MySQL LOAD_FILE
        r"\binto\s+outfile\b",  # MySQL INTO OUTFILE
        r"xp_cmdshell",  # SQL Server command execution
        r"information_schema",  # Accès aux métadonnées
        r"sys\.",  # Accès aux tables système
        r"'\s*;\s*shutdown\b",  # ; SHUTDOWN
    ]

    # Check each pattern
    for pattern in sql_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True

    return False


def detect_xss(url, user_agent, referer):
    search_text = decode_and_combine_fields(url, user_agent, referer)

    # Patterns XSS courants
    xss_patterns = [
        r'<script',  # Balise script
        r'javascript:',  # Protocole javascript
        r'onerror\s*=',  # Event handler onerror
        r'onload\s*=',  # Event handler onload
        r'onclick\s*=',  # Event handler onclick
        r'onmouseover\s*=',  # Event handler onmouseover
        r'<iframe',  # Iframe malveillant
        r'<img[^>]+src',  # Image avec src suspect
        r'alert\s*\(',  # alert() JavaScript
        r'prompt\s*\(',  # prompt() JavaScript
        r'confirm\s*\(',  # confirm() JavaScript
        r'eval\s*\(',  # eval() JavaScript
        r'document\.cookie',  # Accès aux cookies
        r'<svg[^>]*onload',  # SVG avec onload
        r'&#',  # Encodage HTML entities
    ]

    # Check each pattern
    for pattern in xss_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True

    return False


def detect_command_injection(url, user_agent, referer):
    search_text = decode_and_combine_fields(url, user_agent, referer)

    rce_patterns = [
        r";\s*ls\b",  # ; ls
        r";\s*cat\b",  # ; cat
        r";\s*wget\b",  # ; wget
        r";\s*curl\b",  # ; curl
        r";\s*nc\b",  # ; netcat
        r";\s*bash\b",  # ; bash
        r";\s*sh\b",  # ; sh
        r";\s*rm\s+-rf",  # ; rm -rf
        r"\|\s*ls\b",  # | ls (pipe)
        r"\|\s*cat\b",  # | cat
        r"&&\s*",  # && (commande chainée)
        r"`.*`",  # `command` (backticks)
        r"\$\(.*\)",  # $(command)
        r">\s*/dev/null",  # Redirection
        r"2>&1",  # Redirection stderr
        r"/bin/bash",  # Shell complet
        r"/bin/sh",  # Shell
        r"whoami",  # Commande reconnaissance
        r"uname\s+-a",  # Info système
        r"id\b",  # User ID
        r"passwd",  # Modification password
        r"chmod\s+",  # Modification permissions
        r"chown\s+",  # Modification propriétaire
        r"ping\s+-c",  # Ping (SSRF/RCE)
        r"nslookup\s+",  # DNS lookup
        r"powershell",  # PowerShell (Windows)
        r"cmd\.exe",  # CMD Windows
    ]

    for pattern in rce_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True
    return False


def detect_xxe(url, user_agent, referer):

    search_text = decode_and_combine_fields(url, user_agent, referer)

    xxe_patterns = [
        r"<!entity",  # Déclaration entité XML
        r"<!doctype",  # DOCTYPE avec entités
        r"system\s+[\"']file://",  # Lecture fichier local
        r"system\s+[\"']http://",  # SSRF via XXE
        r"<!element",  # Élément XML personnalisé
        r"%\w+;",  # Paramètre entity
        r"&\w+;",  # Entity reference
    ]

    for pattern in xxe_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True
    return False


def detect_ldap_injection(url, user_agent, referer):

    search_text = decode_and_combine_fields(url, user_agent, referer)

    ldap_patterns = [
        r"\*\)\(\|",  # *)( | (wildcard bypass)
        r"\*\)\(uid=\*",  # *)(uid=*
        r"\(\|",  # (| (OR operator)
        r"\(&",  # (& (AND operator)
        r"\)\(",  # )(
        r"admin\*\)\(&",  # admin*)(&
    ]

    for pattern in ldap_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True
    return False


def detect_ssrf(url, user_agent, referer):

    search_text = unquote(url).lower()

    ssrf_patterns = [
        r"localhost",  # localhost
        r"127\.0\.0\.1",  # 127.0.0.1
        r"0\.0\.0\.0",  # 0.0.0.0
        r"::1",  # IPv6 localhost
        r"169\.254\.",  # AWS metadata (169.254.x.x)
        r"metadata",  # Cloud metadata
        r"192\.168\.",  # Private IP
        r"10\.\d+\.\d+\.\d+",  # Private IP 10.x.x.x
        r"172\.(1[6-9]|2[0-9]|3[0-1])\.",  # Private IP 172.16-31.x.x
        r"file://",  # File protocol
        r"gopher://",  # Gopher protocol
        r"dict://",  # Dict protocol
        r"ftp://",  # FTP protocol
    ]

    for pattern in ssrf_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True
    return False


def detect_template_injection(url, user_agent, referer):

    search_text = decode_and_combine_fields(url, user_agent, referer)

    ssti_patterns = [
        r"\{\{.*\}\}",  # {{ }} (Jinja2, Twig)
        r"\${.*}",  # ${ } (Freemarker, Velocity)
        r"<%.*%>",  # <% %> (ERB, JSP)
        r"\{\%.*\%\}",  # {% %} (Jinja2, Twig)
        r"__import__",  # Python import
        r"eval\s*\(",  # eval()
        r"exec\s*\(",  # exec()
        r"\.\_\_class\_\_",  # .__class__ (Python introspection)
        r"\.\_\_mro\_\_",  # .__mro__
        r"\.\_\_subclasses\_\_",  # .__subclasses__
        r"config\.",  # Accès à config (Flask)
    ]

    for pattern in ssti_patterns:
        if re.search(pattern, search_text, re.IGNORECASE):
            return True
    return False


def detect_open_redirect(url):

    decoded_url = unquote(url)

    redirect_patterns = [
        r"redirect=https?://",  # redirect=http://evil.com
        r"url=https?://",  # url=http://evil.com
        r"next=https?://",  # next=http://evil.com
        r"return=https?://",  # return=http://evil.com
        r"redir=https?://",  # redir=http://evil.com
        r"goto=https?://",  # goto=http://evil.com
        r"destination=https?://",  # destination=http://evil.com
        r"view=https?://",  # view=http://evil.com
        r"//evil\.",  # //evil.com (protocol-relative)
        r"@.*\.",  # user@evil.com (URL confusion)
    ]

    for pattern in redirect_patterns:
        if re.search(pattern, decoded_url, re.IGNORECASE):
            return True
    return False


def detect_scanner(user_agent):

    user_agent_lower = user_agent.lower()

    scanner_signatures = [
        'nikto',
        'nmap',
        'masscan',
        'nessus',
        'openvas',
        'sqlmap',
        'metasploit',
        'burp',
        'zap',  # OWASP ZAP
        'acunetix',
        'appscan',
        'w3af',
        'skipfish',
        'arachni',
        'wpscan',
        'dirbuster',
        'gobuster',
        'ffuf',
        'nuclei',
    ]

    for signature in scanner_signatures:
        if signature in user_agent_lower:
            return True
    return False
