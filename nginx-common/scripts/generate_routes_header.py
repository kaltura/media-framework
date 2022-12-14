#!/usr/bin/env python
from utils import writeText
import json
import sys
import os

if len(sys.argv) < 3:
    print('Usage:\n\t%s <routes definition file> <base name>' %
        os.path.basename(__file__))
    sys.exit(1)

INPUT_FILE = sys.argv[1]
BASE_NAME = sys.argv[2]

# Note: must match ngx_http_api_route_node_t
METHODS = ['GET', 'LIST', 'DELETE', 'POST', 'PUT']

HEADER_MACRO = '_%s_ROUTES_H_INCLUDED_' % BASE_NAME.upper()
BASE_VAR_NAME = '%s_route' % BASE_NAME

CHILD_TYPE_NAME = 'ngx_http_api_route_child_t'
NODE_TYPE_NAME = 'ngx_http_api_route_node_t'

def cEscapeString(fixed):
    return json.dumps(fixed)

def parseInputFile(inputFile):
    root = { 'children': {}, 'handlers': {}}
    for curLine in open(inputFile):
        curLine = curLine.strip()
        if len(curLine) == 0:
            continue
        method, path = curLine.split()
        if not method in METHODS:
            print('Unsupported method %s' % method)
            sys.exit(1)
        splittedPath = list(filter(len, path.lstrip('/').split('/')))

        cur = root
        for name in splittedPath:
            cur['children'].setdefault(name, { 'children': {}, 'handlers': {}})
            cur = cur['children'][name]

        handlerName = BASE_NAME
        if len(splittedPath) > 0:
            if len(splittedPath) > 2:
                i = 2
            else:
                i = 0
            while i < len(splittedPath):
                if i + 1 < len(splittedPath) and splittedPath[i + 1] == '%':
                    handlerName += '_%s' % splittedPath[i][:-1]
                    i += 2
                    continue
                handlerName += '_%s' % splittedPath[i]
                i += 1
        handlerName += '_%s' % method.lower()
        cur['handlers'][method] = handlerName
    return root

def outputHeader():
    return '''/* auto-generated by %s */

#ifndef %s
#define %s

''' % (os.path.basename(__file__), HEADER_MACRO, HEADER_MACRO)

def outputNode(node, base):
    result = ''
    children = node['children']
    if len(children) > 0:
        childSpecs = ''
        for name, child in children.items():
            if name == '%':
                childBase = base + '_param'
            else:
                childBase = base + '_' + name
            result += outputNode(child, childBase)
            childSpecs += '    { ngx_string("%s"), &%s },\n' %               \
                (name, childBase)
        childSpecs += '    { ngx_null_string, NULL },\n'
        childrenParam = '%s_children' % base
        result += '''static %s  %s[] = {
%s};


''' % (CHILD_TYPE_NAME, childrenParam, childSpecs)
        childrenParam = '%s' % childrenParam
    else:
        childrenParam = 'NULL'

    handlers = node['handlers']

    if not 'LIST' in handlers and len(children) > 0 and not '%' in children:
        handlerName = base.replace('_route', '') + '_list'
        handlers['LIST'] = handlerName
        childKeys = list(children.keys())
        if node == root:
            childKeys.append('multi')
        childKeys.sort()
        listResponse = cEscapeString(json.dumps(childKeys, separators=(',', ':')))
        result += '''static ngx_int_t %s(ngx_http_request_t *r, ngx_str_t *params, ngx_str_t *response)
{
    ngx_str_set(response, %s);
    return NGX_OK;
}


''' % (handlerName, listResponse)

    handlersArr = ''
    for method in METHODS:
        if method in handlers:
            handlerName = '&%s' % handlers[method]
        else:
            handlerName = 'NULL'

        handlersArr += '    %s,\n' % handlerName
    result += '''static %s  %s = {
    %s,
%s};


''' % (NODE_TYPE_NAME, base, childrenParam, handlersArr)

    return result

def outputFooter():
    return '#endif /* %s */' % HEADER_MACRO

root = parseInputFile(INPUT_FILE)
result = outputHeader() + outputNode(root, BASE_VAR_NAME) + outputFooter()
writeText(result)
