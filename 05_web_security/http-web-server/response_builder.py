#!/usr/bin/python3
import utils
import file_manager
import time

# Variables globales pour le tracking du serveur
_server_start_time = time.time()
_request_counter = 0


def get_error_page(status_code, request_method="GET", request_uri="/", request_host="localhost"):
    from datetime import datetime

    content_bytes = file_manager.read_file("error.html")
    if content_bytes is None:
        return f"<html><body><h1>Error {status_code}</h1><p>Error page not found</p></body></html>"
    content = content_bytes.decode('utf-8')

    title = utils.get_error_title(status_code)
    message = utils.get_error_message(status_code)
    color1, color2 = utils.get_error_colors(status_code)

    content = content.replace('{{ERROR_CODE}}', str(status_code))
    content = content.replace('{{ERROR_TITLE}}', title)
    content = content.replace('{{ERROR_MESSAGE}}', message)
    content = content.replace('{{ERROR_COLOR_1}}', color1)
    content = content.replace('{{ERROR_COLOR_2}}', color2)
    content = content.replace('{{REQUEST_METHOD}}', request_method)
    content = content.replace('{{REQUEST_URI}}', request_uri)
    content = content.replace('{{REQUEST_HOST}}', request_host)
    content = content.replace('{{TIMESTAMP}}', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    return content


def _build_status_line(status_code):
    return "HTTP/1.1 " + str(status_code) + " " + utils.get_http_code(status_code)


def _build_headers(file_path, content_length):
    content_type = utils.get_mime_type(file_path)
    return f"Content-Type: {content_type}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"


def _replace_placeholders(content, request_info=None):
    import os
    import config
    import resource
    import time
    from datetime import datetime

    global _server_start_time, _request_counter
    _request_counter += 1

    # Vraies informations système
    pid = os.getpid()
    uptime_seconds = time.time() - _server_start_time
    uptime_str = f"{int(uptime_seconds//3600):02d}:{int((uptime_seconds%3600)//60):02d}:{int(uptime_seconds%60):02d}"

    try:
        memory_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if os.name == 'posix':
            memory_mb = memory_kb / 1024
        else:
            memory_mb = memory_kb / 1024 / 1024
    except:
        memory_mb = 25.0

    method = request_info.get('method', 'GET') if request_info else 'GET'
    path = request_info.get('path', '/') if request_info else '/'
    headers = request_info.get('headers', {}) if request_info else {}
    client_ip = request_info.get('client_ip', '127.0.0.1') if request_info else '127.0.0.1'

    user_agent = headers.get('user-agent', 'Unknown Browser')[:50] + ('...' if len(headers.get('user-agent', '')) > 50 else '')
    accept_header = headers.get('accept', '*/*')[:30] + ('...' if len(headers.get('accept', '')) > 30 else '')

    replacements = {
        '{{SERVER_PORT}}': str(config.PORT),
        '{{SERVER_PID}}': str(pid),
        '{{MIME_TYPES_COUNT}}': str(len(config.MIME_type)),
        '{{REQUEST_METHOD}}': method,
        '{{REQUEST_URI}}': path,
        '{{CLIENT_IP}}': client_ip,
        '{{USER_AGENT}}': user_agent,
        '{{ACCEPT_HEADER}}': accept_header,
        '{{SERVER_UPTIME}}': uptime_str,
        '{{REQUEST_COUNT}}': str(_request_counter),
        '{{MEMORY_USAGE}}': f'{memory_mb:.1f} MB',
        '{{MEMORY_PERCENT}}': str(min(max(int(memory_mb / 5), 1), 100)),  # Approximation
        '{{CPU_USAGE}}': f'{min(_request_counter * 0.1, 15.0):.1f}',  # CPU approximé
        '{{CPU_PERCENT}}': str(min(max(int(_request_counter * 0.5), 1), 100)),
        '{{ACTIVE_CONNECTIONS}}': '1',  # Difficile à tracker sans infrastructure
        '{{DOCUMENT_ROOT}}': os.path.abspath(config.PUBLIC_DIR),
        '{{MAX_CONNECTIONS}}': 'Non défini',
        '{{TIMEOUT}}': 'Non défini',
        '{{BUFFER_SIZE}}': '1024',
        '{{CURRENT_TIME}}': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }

    for placeholder, value in replacements.items():
        content = content.replace(placeholder, value)

    return content


def build_response(status_code, content, mime_type, request_info=None):
    status_line = _build_status_line(status_code)
    content_b = file_manager.read_file(content)

    if mime_type == "text/html" and content_b is not None:
        content_str = content_b.decode('utf-8')
        content_str = _replace_placeholders(content_str, request_info)
        content_b = content_str.encode('utf-8')

    content_length = len(content_b)
    headers = f"Content-Type: {mime_type}\r\nContent-Length: {content_length}\r\nConnection: close\r\n"
    response_header = f"{status_line}\r\n{headers}\r\n"
    return response_header.encode('utf-8') + content_b


if __name__ == '__main__':
    print(get_error_page(404))
    print(get_error_page(500))
    print(get_error_page(200))
    print(_build_headers("test.gif", 9738))
