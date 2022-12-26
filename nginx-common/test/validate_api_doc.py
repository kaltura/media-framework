#!/usr/bin/env python

import os
import re


def parse_source(path, out):
    path = os.path.normpath(path)
    with open(path) as f:
        data = f.read()

    for cur_line in data.split('\n'):
        cur_line = cur_line.strip()
        if cur_line == '':
            continue

        out.append(re.sub(' +', ' ', cur_line))

def scan_source_dir(top, out):
    for root, _, files in os.walk(top):
        for name in files:
            if not name.endswith('routes.txt'):
                continue

            path = os.path.join(root, name)
            if 'unused' in path or 'old' in path:
                continue

            parse_source(path, out)

def parse_readme(path, out):
    path = os.path.normpath(path)
    with open(path) as f:
        data = f.read()
    line_num = 0

    hdr_level = -1
    for cur_line in data.split('\n'):
        line_num += 1

        if not cur_line.startswith('#'):
            continue

        level = len(re.match('^#*', cur_line).group())

        if 'api endpoints' in cur_line.lower():
            if hdr_level < 0:
                hdr_level = level
            continue

        if hdr_level < 0:
            continue

        if level <= hdr_level:
            hdr_level = -1
            continue

        route = cur_line.lstrip('#').strip()
        route = re.sub('{[^}]+}', '%', route)
        if route.startswith('GET ') and route.endswith('?list=1'):
            route = 'LIST ' + route[len('GET '):-len('?list=1')]

        if route in out:
            print('Warning: duplicate API endpoint \"%s\", in %s:%s' % (route, path, line_num))
        out[route] = (path, line_num)


base_dir = os.path.join(os.path.dirname(__file__), '../..')
base_dir = os.path.normpath(base_dir)

module_list = filter(lambda x: x.startswith('nginx'), os.listdir(base_dir))

for module in module_list:

    print('\n%s\n%s' % (module, '-' * len(module)))
    module_base = os.path.join(base_dir, module)
    readme_path = os.path.join(module_base, 'README.md')

    src_routes = []
    scan_source_dir(module_base, src_routes)

    doc_routes = {}
    if os.path.isfile(readme_path):
        parse_readme(readme_path, doc_routes)

    undoc_routes = set(src_routes) - set(doc_routes)
    non_exist_routes = set(doc_routes) - set(src_routes)

    print('Info: ok, %s documented routes' % len(doc_routes))

    if len(undoc_routes) > 0:
        print('Error: undocumented routes: %s' % undoc_routes)

    if len(non_exist_routes) > 0:
        print('Error: routes missing from src: %s' % non_exist_routes)
