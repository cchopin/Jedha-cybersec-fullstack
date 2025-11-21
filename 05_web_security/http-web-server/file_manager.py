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


def read_file(file_path):
    if file_exists(file_path):
        my_file = open(f"public/{resolve_file_path(file_path)}", "rb")
        my_data = my_file.read()
        my_file.close()
        return my_data
    else:
        return 404


if __name__ == '__main__':
    print(resolve_file_path("../../hello"))
    print(file_exists("test.html"))
    print(file_exists("../test.html"))
    print(file_exists("public/testdd.html"))
