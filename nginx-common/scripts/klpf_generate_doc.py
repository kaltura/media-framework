import json
import sys
import os

def format_name(s):
    return s.title().replace('_', ' ')

def print_fields(fields, indent=''):
    for field in fields:
        type = field['type']
        name = field['name']
        count = field['count']
        children = field['children']

        if len(children) == 0:
            name = '**%s**' % name
        else:
            name = '*%s*' % name

        if count != '1':
            if count != '':
                count = '*%s*' % count
            name = '%s[%s]' % (name, count)

        print('%s- %s %s' % (indent, type, name))
        print_fields(children, indent + '    ')

def print_blocks(parent, ctx=''):
    for block in parent['children']:
        id = block['id']
        name = format_name(block['name'])

        print('## %s Block (`%s`)' % (name, id))
        if ctx != '':
            print('Context: *%s*' % ctx)
            print()

        for field_type in ['header', 'data']:
            fields = block[field_type]
            if len(fields) == 0:
                continue

            print('### Block %s' % format_name(field_type))
            print_fields(fields)
            print()

        sub_ctx = '%s Block' % name
        print_blocks(block, sub_ctx)

if len(sys.argv) < 2:
    print('Usage:\n\t%s <persist spec>' % os.path.basename(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[1]) as f:
    spec = json.load(f)

for file_type in spec:
    print('# %s File (`%s`)' % (format_name(file_type['name']),
        file_type['id']))
    print_blocks(file_type)
