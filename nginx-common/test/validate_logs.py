#!/usr/bin/env python

from __future__ import print_function
from common import *
import sys
import re
import os

IGNORE_MODULES = [
    'nginx-rtmp-module',
    'nginx-mpegts-module'
]

IGNORE_FILES = set([
    'ngx_http_call.c',
    'ngx_kmp_rtmp_handshake.c',
    'ngx_live_map.c',
    'ngx_live_variables.c',
    'ngx_live_script.c', 'cea708.c'
])

IGNORE_FUNCS = set([
    'ngx_live_preset_names',
    'ngx_live_segmenter_kf_list_dump',
    'ngx_live_segmenter_dump_track',
    'ngx_http_pckg_capture_init_frame_processor',
    'ngx_http_complex_value_flag',
    'ngx_http_complex_value_percent',
    'ngx_http_pckg_extract_string',
])

def count_args(args_spec):
    result = 0
    parent_count = 0
    for ch in args_spec:
        if ch == '(':
            parent_count += 1
        elif ch == ')':
            parent_count -= 1
        elif ch == ',' and parent_count == 0:
            result += 1
    return result

def ignore_path(file_path):
    if os.path.basename(file_path) in IGNORE_FILES:
        return True
    for module in IGNORE_MODULES:
        if module in file_path:
            return True
    return False

def process_file(file_path):
    file_data = open(file_path, 'r').read()

    for m in re.finditer('(?:ngx|vod)_log_(?:debug|error)[^\(]*\(', file_data):

        # get the full log line (spanning on multiple lines)
        pos = m.start()
        while True:
            pos = file_data.find(')', pos) + 1
            cur_log = file_data[m.start():pos]
            if cur_log.count('(') == cur_log.count(')'):
                break;

        line_pos = file_data.find(cur_log)

        log_args = cur_log.split(',', 3)[-1]

        # extract the log message (may be composed of multiple strings)
        log_msg = ''
        while True:
            log_args = log_args.strip()
            if log_args.startswith(','):
                break

            start = log_args.find('"')
            if start < 0:
                break

            start += 1
            pos = start
            while True:
                next = log_args.find('"', pos)
                pos = next + 1
                if log_args[next - 1] != '\\':
                    break

            log_msg += log_args[start:next]
            log_args = log_args[pos:]

        if log_args.startswith('const char *fmt'):
            continue

        # validate arg count
        if count_args(log_args) != log_msg.count('%') + log_msg.count('%*'):
            report_err('Error: log args mismatch, args: %s, line:\n\t%s' % (log_args, log_msg))

        if ignore_path(file_path):
            continue

        # validate the function name in the log matches the actual function
        func_names = re.findall('^[a-z0-9_]+\(', file_data[:line_pos], re.MULTILINE)
        real_func = func_names[-1] if len(func_names) > 0 else ''
        if real_func.endswith('('):
            real_func = real_func[:-1]

        log_func = log_msg.split(':')[0]

        if real_func != log_func and real_func not in IGNORE_FUNCS:
            report_err('Error: log function mismatch, expected: "%s", got: "%s", line:\n\t%s' % (real_func, log_func, log_msg))


base_dir = get_base_dir()

for root, _, files in os.walk(base_dir):
    for name in files:
        if os.path.splitext(name)[1] != '.c':
            continue

        file_path = os.path.join(root, name)
        if 'unused' in file_path:
            continue

        process_file(file_path)

exit()
