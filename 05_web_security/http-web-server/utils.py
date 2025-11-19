#!/usr/bin/python3
import config
from config import HOST, PORT, http_code, MIME_type
import string


def get_mime_type(file_path):
    try:
        pos = file_path.rindex(".")
        extension = file_path[pos:]
        return config.MIME_type.get(extension, "application/octet-stream")
    except ValueError:
        # Pas d'extension trouvée
        return "application/octet-stream"


def get_http_code(status_code):
    return config.http_code[status_code]


if __name__ == '__main__':
    print(get_mime_type("test.html"))
    print(get_mime_type("test.css"))
    print(get_mime_type("test.js"))
    print(get_mime_type("test.jpg"))
    print(get_mime_type("test.png"))
    print(get_mime_type("test.gif"))
    print(get_mime_type("test.txt"))
    print(get_http_code(200))
    print(get_http_code(404))
    print(get_http_code(500))
