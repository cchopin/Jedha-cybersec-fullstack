#!/usr/bin/python3

HOST = "0.0.0.0"
PORT = 8000
PUBLIC_DIR = "public"


http_code = {
    200: "ok",
    404: "Not Found",
    403: "Forbidden",
    405: "Method Not Allowed",
    500: "Internal Server Error"
}

MIME_type = {
    ".html": "text/html",
    ".css": "text/css",
    ".js": "application/javascript",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".png": "image/png",
    ".gif": "image/gif",
    ".txt": "application/octet-stream"
}
