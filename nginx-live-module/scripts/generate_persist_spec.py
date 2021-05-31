#!/usr/bin/env python
import binascii
import re
import os

STATE_INITIAL = 'initial'
STATE_COMMENT = 'comment'
STATE_STRUCT = 'struct'
STATE_UNION = 'union'
STATE_PERSIST = 'persist'

TYPEDEF_ALIAS = 'alias'

defines = {}
typedefs = {}
specs = []

def parse_source(data):
    global defines, typedefs, specs

    state = STATE_INITIAL
    for cur_line in data.split('\n'):
        if state in set([STATE_STRUCT, STATE_UNION]):
            if not cur_line.startswith('}'):
                block += cur_line + '\n'
                continue
            if name is None:
                name = cur_line[1:].strip().rstrip(';')
            typedefs[name] = (block, state)
            state = STATE_INITIAL
            continue

        elif state == STATE_COMMENT:
            if not '*/' in cur_line:
                block += cur_line + '\n'
                continue
            if 'persist header:' in block or 'persist data:' in block:
                persist_spec = block
                state = STATE_PERSIST
                block = ''
            else:
                state = STATE_INITIAL
            continue

        elif state == STATE_PERSIST:
            block += cur_line + '\n'
            if not '}' in cur_line:
                continue
            block = block[(block.find('{') + 1):block.rfind('}')]
            specs.append((persist_spec, [x.strip() for x in block.split(',')]))
            state = STATE_INITIAL
            continue

        # state == STATE_INITIAL
        if cur_line.startswith('#define'):
            split_line = cur_line.split(None, 2)
            if len(split_line) > 2:
                defines[split_line[1]] = split_line[2]

        elif cur_line.startswith('typedef struct {'):
            state = STATE_STRUCT
            name = None
            block = ''

        elif cur_line.startswith('typedef union {'):
            state = STATE_UNION
            name = None
            block = ''

        elif cur_line.startswith('typedef '):
            split = cur_line.split()
            if len(split) == 3:
                name = split[2].strip(';')
                typedefs[name] = (split[1], TYPEDEF_ALIAS)

        elif cur_line.startswith('struct '):
            state = STATE_STRUCT
            name = cur_line.split()[1]
            block = ''

        elif cur_line.strip().endswith('/*'):
            state = STATE_COMMENT
            block = ''

def scan_source_dir(top):
    for root, dirs, files in os.walk(top):
        for name in files:
            if not os.path.splitext(name)[1] in set(['.c', '.h']):
                continue
            data = open(os.path.join(root, name)).read()
            parse_source(data)

def get_id_value(s):
    global defines

    while s in defines:
        s = defines[s]

    comment_pos = s.find('/*')
    if comment_pos >= 0:
        s = s[:comment_pos]

    s = s.strip().strip('()')
    if not s.startswith('0x'):
        print('Error: id "%s" does not start with "0x"' % s)
        return None

    return binascii.unhexlify(s[2:])[::-1].decode('utf8')

def parse_struct(s):
    global typedefs, defines

    result = []
    if s == '':
        return result

    for cur_line in s.split('\n'):
        if ';' in cur_line:
            cur_line = cur_line[:cur_line.find(';')]

        split_line = cur_line.split()
        if len(split_line) < 2:
            continue

        type_name = split_line[-2]
        var_name = split_line[-1]

        brack_pos = var_name.find('[')
        if brack_pos >= 0:
            array_count = var_name[(brack_pos + 1):var_name.rfind(']')]
            var_name = var_name[:brack_pos]
            if array_count in defines:
                array_count = defines[array_count].strip('()')
            elif array_count == '':
                array_count = 'max'
        else:
            array_count = '1'

        while True:
            struct_def = ''
            if type_name in typedefs:
                struct_def, type_name = typedefs[type_name]
            elif type_name.endswith('_t') and (type_name[:-2] + '_s') in typedefs:
                struct_def, type_name = typedefs[type_name[:-2] + '_s']
            if type_name != TYPEDEF_ALIAS:
                break
            type_name = struct_def

        result.append((type_name, var_name, array_count,
            parse_struct(struct_def)))

    return result

def print_fields(fields, indent='\t'):
    for cur_field in fields:
        print(indent + '\t'.join(cur_field[:-1]))
        sub_fields = cur_field[-1]
        if len(sub_fields) > 0:
            print_fields(sub_fields, indent + '\t')

def print_block(file_type, block_id, type, fields):
    print('_'.join([file_type, block_id, type]))
    print_fields(fields)
    print('')

def print_spec():
    global specs

    for format, params in specs:
        id, ctx = params[:2]

        block_id = get_id_value(id)

        if not ctx.startswith('NGX_LIVE_PERSIST_CTX_'):
            print('Error: invalid prefix for ctx "%s"' % ctx)
            continue
        ctx = ctx[len('NGX_LIVE_PERSIST_CTX_'):]
        file_type = ctx.split('_')[0]
        file_type = get_id_value('NGX_LIVE_PERSIST_TYPE_%s' % file_type)

        fields = []
        cur_struct = ''
        for cur_line in format.split('\n'):
            if 'persist header:' in cur_line:
                if len(cur_struct) > 0:
                    print_block(file_type, block_id, type,
                        parse_struct(cur_struct))
                type = 'header'
                cur_struct = ''
                continue
            elif 'persist data:' in cur_line:
                if len(cur_struct) > 0:
                    print_block(file_type, block_id, type,
                        parse_struct(cur_struct))
                type = 'data'
                cur_struct = ''
                continue

            cur_line = cur_line.strip().strip('*')
            cur_struct += cur_line + '\n'

        if len(cur_struct) > 0:
            print_block(file_type, block_id, type, parse_struct(cur_struct))

base_dir = os.path.join(os.path.dirname(__file__), '../..')
scan_source_dir(os.path.join(base_dir, 'nginx-common/src'))
scan_source_dir(os.path.join(base_dir, 'nginx-live-module/src'))
typedefs['ngx_str_t'] = ('uint32_t len;\nu_char data[len];', 'struct')
print_spec()
