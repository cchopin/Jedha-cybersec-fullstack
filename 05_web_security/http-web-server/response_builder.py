#!/usr/bin/python3
import utils
import file_manager


def get_error_page(status_code):
    return utils.get_http_code(status_code)


def build_status_line(status_code):
    return "HTTP/1.1 " + status_code + " " + get_error_page(status_code)


def build_headers(file_path, content_length):
    content_type = utils.get_mime_type(file_path)
    return f"Content-Type: {content_type}\r\nContent-Length: {content_length}\r\nConnection: close\r\n\r\n"


def build_response(status_code, content, mime_type):
    status_line = build_status_line(status_code)
    content_b = file_manager.read_file(content)
    content_length = len(content_b)
    headers = f"Content-Type: {mime_type}\r\nContent-Length: {content_length}\r\nConnection: close"
    response_header = f"{status_line}\r\n{headers}\r\n\r\n"
    return response_header.encode('utf-8') + content_b


if __name__ == '__main__':
    print(get_error_page(404))
    print(get_error_page(500))
    print(get_error_page(200))
    print(build_headers("test.gif", 9738))
