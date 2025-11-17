#!/usr/bin/env python3
import re
from urllib.parse import unquote
import base64


def detect_jwt(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}"

    # Pattern pour détecter un JWT (3 parties séparées par des points)
    jwt_pattern = r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*'

    jwt_matches = re.findall(jwt_pattern, content)

    for jwt in jwt_matches:
        parts = jwt.split('.')
        if len(parts) != 3:
            continue

        header = parts[0]
        payload = parts[1]
        signature = parts[2]

        try:
            # Décode le header (ajout du padding si nécessaire)
            header_padded = header + '=' * (4 - len(header) % 4)
            decoded_header = base64.urlsafe_b64decode(header_padded).decode('utf-8').lower()

            # Décode le payload
            payload_padded = payload + '=' * (4 - len(payload) % 4)
            decoded_payload = base64.urlsafe_b64decode(payload_padded).decode('utf-8').lower()

            # Patterns d'attaques JWT dans le header
            jwt_header_attacks = [
                r'"alg"\s*:\s*"none"',  # Algorithm None attack
                r'"typ"\s*:\s*"none"',  # Type None
                r'"alg"\s*:\s*"hs256".*"typ"\s*:\s*"jwt".*"alg"\s*:\s*"rs256"',  # Algorithm confusion
                r'"jku"\s*:',  # JKU header injection
                r'"x5u"\s*:',  # X5U header injection
                r'"kid"\s*:\s*".*\.\./.*"',  # Path traversal dans kid
                r'"kid"\s*:\s*".*/etc/passwd"',  # Path traversal vers fichier sensible
                r'"kid"\s*:\s*".*sql.*"',  # SQL injection dans kid
            ]

            # Patterns d'attaques JWT dans le payload
            jwt_payload_attacks = [
                r'"admin"\s*:\s*true',  # Escalade de privilèges
                r'"role"\s*:\s*"admin"',  # Modification du rôle
                r'"exp"\s*:\s*9999999999',  # Expiration très longue
                r'"iat"\s*:\s*-',  # Timestamp négatif
                r'"nbf"\s*:\s*-',  # Not Before négatif
                r'"sub"\s*:\s*"admin"',  # Changement de subject
                r'"aud"\s*:\s*"\*"',  # Audience wildcard
            ]

            # Vérifie les attaques dans le header
            for pattern in jwt_header_attacks:
                if re.search(pattern, decoded_header, re.IGNORECASE):
                    return True

            # Vérifie les attaques dans le payload
            for pattern in jwt_payload_attacks:
                if re.search(pattern, decoded_payload, re.IGNORECASE):
                    return True

            # Signature vide ou invalide (None algorithm)
            if signature == '' or signature == 'none':
                return True

        except Exception:
            # Si on ne peut pas décoder, c'est peut-être manipulé
            continue

    # Détecte aussi les patterns d'attaques JWT sans décoder
    jwt_attack_patterns = [
        r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.',  # JWT sans signature
        r'"alg":"none"',  # Algorithm None dans l'URL
        r'authorization.*bearer.*eyj.*eyj\.',  # Token JWT dans Authorization
    ]

    for pattern in jwt_attack_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    return False


def detect_lfi(url, user_agent, referer):
    # Décode les URL encodées (important pour %2e%2e%2f → ../)
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)

    # Combine tous les champs
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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

    # Vérifie chaque pattern
    for pattern in traversal_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    return False


def detect_sql(url, user_agent, referer):
    # Décode les URL encodées
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)

    # Combine tous les champs à analyser
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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

    # Vérifie chaque pattern
    for pattern in sql_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    return False


def detect_xss(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)

    # Combine TOUS les champs à analyser (url + user_agent + referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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

    # Vérifie chaque pattern
    for pattern in xss_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True

    return False


def detect_command_injection(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def detect_xxe(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def detect_ldap_injection(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

    ldap_patterns = [
        r"\*\)\(\|",  # *)( | (wildcard bypass)
        r"\*\)\(uid=\*",  # *)(uid=*
        r"\(\|",  # (| (OR operator)
        r"\(&",  # (& (AND operator)
        r"\)\(",  # )(
        r"admin\*\)\(&",  # admin*)(&
    ]

    for pattern in ldap_patterns:
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def detect_ssrf(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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
        if re.search(pattern, content, re.IGNORECASE):
            return True
    return False


def detect_template_injection(url, user_agent, referer):
    decoded_url = unquote(url)
    decoded_user_agent = unquote(user_agent)
    decoded_referer = unquote(referer)
    content = f"{decoded_url} {decoded_user_agent} {decoded_referer}".lower()

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
        if re.search(pattern, content, re.IGNORECASE):
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
    ua_lower = user_agent.lower()

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

    for scanner in scanner_signatures:
        if scanner in ua_lower:
            return True
    return False
