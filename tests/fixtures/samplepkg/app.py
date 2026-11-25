"""Fixture: one vulnerable and one safe use-site."""
import re
from flask import request

VULN = "^(a+)+$"
SAFE = re.compile(r"^[a-z]+$")


def handler():
    return re.match(VULN, request.args.get("q", ""))


def safe_handler():
    return SAFE.match("abc")


def local_handler():
    import sys
    return re.match(r"^(b+)+$", sys.argv[1])
