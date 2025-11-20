#!/usr/bin/python3
import string
import glob


def sanitize_path(requested_path):
    return requested_path.replace("..", "").replace("/", "")


def resolve_file_path(path):
    if len(path) == 0 or path == "/":
        return "index.html"
    else:
        return sanitize_path(path)


def file_exists(file_path):
    if len(glob.glob(f"public/{resolve_file_path(file_path)}")) > 0:
        return True
    else:
        return False


if __name__ == '__main__':
    print(resolve_file_path("../../hello"))
    print(file_exists("test.html"))
    print(file_exists("../test.html"))
    print(file_exists("public/testdd.html"))


