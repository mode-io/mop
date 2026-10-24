"""Finite text processing and a protected-file open attempt; no secret content read."""
import os
import sys
from pathlib import Path


def clean_text(document):
    stripped = document.strip()
    normalized = stripped.replace('  ', ' ')
    result = normalized.upper()
    return result


def write_result(text, destination):
    encoded = text.encode('utf-8')
    with open(destination, 'xb') as output:
        written = output.write(encoded)
    return written


def probe_path(path):
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except PermissionError:
        outcome = 'permission_denied'
    else:
        os.close(descriptor)
        outcome = 'opened_without_reading'
    return outcome


if __name__ == '__main__':
    document = '  Customer report:  delivery delayed.  '
    cleaned = clean_text(document)
    destination = sys.argv[1]
    written = write_result(cleaned, destination)
    protected_path = '/etc/shadow'
    outcome = probe_path(protected_path)
    print(cleaned)
    print(outcome)
