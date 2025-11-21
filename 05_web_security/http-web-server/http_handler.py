#!/usr/bin/python3
import sys
import re
from urllib.parse import unquote


def parse_request(raw_request):
    lines = re.split(r'\r?\n', raw_request)

    method, path, version = lines[0].split(' ')
    decoded_path = unquote(path)

    headers = {}
    for line in lines[1:]:
        if line == '':
            break
        key, value = line.split(': ', 1)
        headers[key] = value

    return {
        'method': method,
        'path': decoded_path,
        'version': version,
        'headers': headers
    }


if __name__ == '__main__':
    if len(sys.argv) > 1:
        test_request = sys.argv[1]
        print(parse_request(test_request))
    else:
        print("Usage: python main.py 'GET /test.html HTTP/1.1\\r\\n...'")
