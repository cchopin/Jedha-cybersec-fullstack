#!/usr/bin/python3
import os
import config
from typing import Optional


def _sanitize_path(requested_path: str) -> str:
    if not isinstance(requested_path, str):
        return ""
    path = os.path.normpath(requested_path.strip())
    path = path.replace("..", "").replace("\\", "")
    if path.startswith("/"):
        path = path[1:]
    return path


def _resolve_file_path(path: Optional[str]) -> str:
    if not path or path == "/" or path == "":
        return "index.html"
    return _sanitize_path(path)


def file_exists(file_path: str) -> bool:
    full_path = os.path.join(config.PUBLIC_DIR, _resolve_file_path(file_path))
    return os.path.isfile(full_path)


def read_file(file_path: str) -> Optional[bytes]:
    full_path = os.path.join(config.PUBLIC_DIR, _resolve_file_path(file_path))

    try:
        with open(full_path, "rb") as file:
            return file.read()
    except (FileNotFoundError, PermissionError, OSError):
        return None


if __name__ == '__main__':
    print(file_exists("test.html"))
    print(file_exists("../test.html"))
    print(file_exists("public/testdd.html"))
