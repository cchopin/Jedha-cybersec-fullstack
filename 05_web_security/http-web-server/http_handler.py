#!/usr/bin/python3
import sys
import re
import file_manager
import response_builder
import utils
from urllib.parse import unquote


def parse_request(raw_request):
    if not raw_request or not raw_request.strip():
        return None

    lines = re.split(r'\r?\n', raw_request)

    if not lines or len(lines) < 1:
        return None

    try:
        request_line = lines[0].split(' ')
        if len(request_line) != 3:
            return None

        method, path, version = request_line
        decoded_path = unquote(path)

        headers = {}
        for line in lines[1:]:
            if line == '':
                break
            if ': ' in line:
                key, value = line.split(': ', 1)
                headers[key.lower()] = value

        return {
            'method': method.upper(),
            'path': decoded_path,
            'version': version,
            'headers': headers
        }

    except (ValueError, IndexError):
        return None


def route_request(method, path, headers=None):
    def get_error_response(error_code):
        request_host = headers.get('host', 'localhost') if headers else 'localhost'
        request_file = response_builder.get_error_page(error_code, method, path, request_host)
        return error_code, request_file

    if method not in ['GET', 'POST', 'PUT', 'DELETE', 'HEAD']:
        return get_error_response(405)

    if method == 'GET':
        if file_manager.file_exists(path):
            # Résoudre le chemin du fichier (/ -> index.html)
            if not path or path == "/" or path == "":
                resolved_path = "index.html"
            else:
                resolved_path = path.lstrip('/')
            return 200, resolved_path
        else:
            return get_error_response(404)
    else:
        return get_error_response(405)


def _send_error_response(client_socket, status_code):
    try:
        error_content = response_builder.get_error_page(status_code, "UNKNOWN", "/", "localhost")
        response = f"HTTP/1.1 {status_code} {utils.get_http_code(status_code)}\r\n"
        response += f"Content-Type: text/html\r\nContent-Length: {len(error_content)}\r\n\r\n"
        response += error_content
        client_socket.sendall(response.encode('utf-8'))
    except (ConnectionError, BrokenPipeError):
        pass


def handle_client(client_socket):
    try:
        client_address = client_socket.getpeername()[0]

        raw_request = client_socket.recv(1024).decode('utf-8')

        parsed_request = parse_request(raw_request)

        print(f"Request received: {raw_request[:100]}...")

        if not parsed_request:
            error_content = response_builder.get_error_page(400, "UNKNOWN", "/", "localhost")
            response = f"HTTP/1.1 400 {utils.get_http_code(400)}\r\n"
            response += f"Content-Type: text/html\r\nContent-Length: {len(error_content)}\r\n\r\n"
            response += error_content
            client_socket.sendall(response.encode('utf-8'))
            return

        method = parsed_request['method']
        path = parsed_request['path']
        headers = parsed_request['headers']

        request_info = {
            'method': method,
            'path': path,
            'headers': headers,
            'client_ip': client_address
        }

        status_code, content = route_request(method, path, headers)

        if status_code == 200:
            mime_type = utils.get_mime_type(content)
            response = response_builder.build_response(status_code, content, mime_type, request_info)
        else:
            response = f"HTTP/1.1 {status_code} {utils.get_http_code(status_code)}\r\n"
            response += f"Content-Type: text/html\r\nContent-Length: {len(content)}\r\n\r\n"
            response += content
            response = response.encode('utf-8')

        client_socket.sendall(response)

    except (UnicodeDecodeError, ConnectionError, BrokenPipeError) as e:
        print(f"Network error handling client: {e}")
        _send_error_response(client_socket, 500)
    except Exception as e:
        print(f"Unexpected error handling client: {e}")
        _send_error_response(client_socket, 500)

    finally:
        try:
            client_socket.close()
        except OSError:
            pass


if __name__ == '__main__':
    if len(sys.argv) > 1:
        test_request = sys.argv[1]
        print(parse_request(test_request))
    else:
        print("Usage: python main.py 'GET /test.html HTTP/1.1\\r\\n...'")

