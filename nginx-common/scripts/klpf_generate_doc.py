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
        name = block['name']
        link = block['link']

        print('## %s (`%s`)' % (name, id))
        if ctx != '':
            print('Parent: %s' % ctx)
            print()

        children = ', '.join(map(lambda x: x['link'], block['children']))
        if children != '':
            print('Children: %s' % children)
            print()

        for field_type in ['header', 'data']:
            fields = block[field_type]
            if len(fields) == 0:
                continue

            print('### Block %s' % format_name(field_type))
            print_fields(fields)
            print()

        print_blocks(block, link)

def set_block_links(parent, seen_anchor_ids):
    for block in parent['children']:
        name = format_name(block['name']) + ' Block'
        block['name'] = name

        anchor_id = '%s %s' % (name, block['id'])
        anchor_id = anchor_id.replace(' ', '-').lower()

        if anchor_id in seen_anchor_ids:
            i = 1
            while True:
                cur_anchor_id = '%s-%s' % (anchor_id, i)
                if cur_anchor_id not in seen_anchor_ids:
                    anchor_id = cur_anchor_id
                    break
                i += 1

        block['link'] = '[*%s*](#%s)' % (name, anchor_id)
        seen_anchor_ids.add(anchor_id)

        set_block_links(block, seen_anchor_ids)

if len(sys.argv) < 2:
    print('Usage:\n\t%s <persist spec>' % os.path.basename(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[1]) as f:
    spec = json.load(f)

seen_anchor_ids = set([])
for file_type in spec:
    set_block_links(file_type, seen_anchor_ids)

for file_type in spec:
    print('# %s File (`%s`)' % (format_name(file_type['name']),
        file_type['id']))
    print_blocks(file_type)
