#!/usr/bin/env python

from common import *
import sys
import re
import os


def get_quoted_str(s):
    start = s.find('"')
    if start < 0:
        return None

    end = s.rfind('"')
    s = s[(start + 1):end]

    return re.sub(r'(?<!\\)"\s+"', '', s)

def process_file(file_path):
    file_data = open(file_path, 'r').read()

    sizeofs = set(map(get_quoted_str, re.findall('sizeof\(([^)]*)\)', file_data)))
    copies = set(map(get_quoted_str, re.findall('ngx_copy_fix\(([^)]*)\)', file_data)))

    missing_sizeof = copies - sizeofs - set(["true"])
    for s in missing_sizeof:
        report_err('Error: missing sizeof for %s in %s' % (s, file_path))


base_dir = get_base_dir()

for root, _, files in os.walk(base_dir):
    for name in files:
        if os.path.splitext(name)[1] not in ['.c', '.h']:
            continue

        file_path = os.path.join(root, name)
        process_file(file_path)

exit()
