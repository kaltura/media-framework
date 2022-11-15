#!/usr/bin/env python
import binascii
import json
import sys
import re
import os


SOURCE_SCAN_PATHS = ['nginx-common/src', 'nginx-live-module/src']

PERSIST_SECTION_START = 'static ngx_persist_block_t  '
PERSIST_SECTION_END = 'ngx_null_persist_block'

PERSIST_TYPE_PREFIX  = 'NGX_LIVE_PERSIST_TYPE_'
PERSIST_CTX_PREFIX = 'NGX_LIVE_PERSIST_CTX_'
PERSIST_CTX_MAIN = 'MAIN'
PERSIST_PARENT_ID_MAP = {
    'SEGMENT_HEADER': 'SEGMENT',
    'SEGMENT_DATA': 'SEGMENT',
    'FILLER_HEADER': 'SEGMENT',
    'FILLER_DATA': 'SEGMENT',
    'BUCKET': 'MAIN',
}

PERSIST_BLOCK_NAME_STRIP = ['NGX_LIVE', 'NGX_KSMP_BLOCK', 'PERSIST_BLOCK']

PERSIST_FILE_MAGIC = 'NGX_PERSIST_FILE_MAGIC'
PERSIST_FILE_HEADER = 'ngx_persist_file_header_t'

PERSIST_EXTRA_TYPES = {
    'ngx_str_t': ('uint32_t len;\nu_char data[len];', 'struct'),
}

STATE_INITIAL = 'initial'
STATE_PERSIST = 'persist'
STATE_PERSIST_COMMENT = 'comment'
STATE_STRUCT = 'struct'
STATE_UNION = 'union'
STATE_DEFINE = 'define'

TYPEDEF_ALIAS = 'alias'


class JsonObjectEncoder(json.JSONEncoder):
    def default(self, o):
        if hasattr(o, 'json_dict'):
            return o.json_dict()
        return o.__dict__

class PersistFileType:
    def __init__(self, id, name):
        self.id = id
        self.name = name
        self.children = []

        self.blocks_by_name = {}

    def json_dict(self):
        return { k: getattr(self, k) for k in
            ['id', 'name', 'children'] }

class PersistBlock:
    def __init__(self, id, name, parent_id='', path='', line_num=0):
        self.id = id
        self.name = name
        self.header = []
        self.data = []
        self.children = []

        self.parent_ids = set([parent_id])
        self.path = path
        self.line_num = line_num

    def json(self):
        return json.dumps(self, cls=JsonObjectEncoder)

    def json_dict(self):
        return { k: getattr(self, k) for k in
            ['id', 'name', 'header', 'data', 'children'] }

class PersistBlockField:
    def __init__(self, type, name, count, children):
        self.type = type
        self.name = name
        self.count = count
        self.children = children


defines = {}
typedefs = {}
specs = []

def parse_source(path):
    global defines, typedefs, specs

    path = os.path.normpath(path)
    with open(path) as f:
        data = f.read()
    line_num = 0

    state = STATE_INITIAL
    for cur_line in data.split('\n'):
        line_num += 1

        if state in set([STATE_STRUCT, STATE_UNION]):
            if not cur_line.startswith('}'):
                block += cur_line + '\n'
                continue

            if name is None:
                name = cur_line[1:].strip().rstrip(';')
            typedefs[name] = (block, state)
            state = STATE_INITIAL
            continue

        elif state == STATE_PERSIST:
            if PERSIST_SECTION_END in cur_line:
                state = STATE_INITIAL
                continue

            if cur_line.strip().endswith('/*'):
                state = STATE_PERSIST_COMMENT
                block = ''
                continue

            block += cur_line + '\n'
            if not '}' in cur_line:
                continue

            block = block[(block.find('{') + 1):block.rfind('}')]
            specs.append((persist_spec, [x.strip() for x in block.split(',')],
                path, line_num))
            persist_spec = ''
            continue

        elif state == STATE_PERSIST_COMMENT:
            if not '*/' in cur_line:
                block += cur_line + '\n'
                continue

            persist_spec = block
            state = STATE_PERSIST
            block = ''
            continue

        elif state == STATE_DEFINE:
            define_value = cur_line.strip()
            if define_value.endswith('\\'):
                define_value = define_value[:-1]
            else:
                state = STATE_INITIAL
            defines[define_name] += define_value
            continue

        # state == STATE_INITIAL
        if PERSIST_SECTION_START in cur_line:
            state = STATE_PERSIST
            block = ''
            persist_spec = ''

        elif cur_line.startswith('#define'):
            split_line = cur_line.split(None, 2)
            define_name = split_line[1]
            define_value = ' '.join(split_line[2:])
            if define_value.endswith('\\'):
                define_value = define_value[:-1]
                state = STATE_DEFINE
            defines[define_name] = define_value

        elif cur_line.startswith('typedef struct {'):
            state = STATE_STRUCT
            block = ''
            name = None

        elif cur_line.startswith('typedef union {'):
            state = STATE_UNION
            block = ''
            name = None

        elif cur_line.startswith('typedef '):
            split = cur_line.split()
            if len(split) == 3:
                name = split[2].strip(';')
                typedefs[name] = (split[1], TYPEDEF_ALIAS)

        elif cur_line.startswith('struct '):
            state = STATE_STRUCT
            block = ''
            name = cur_line.split()[1]

def scan_source_dir(top):
    for root, dirs, files in os.walk(top):
        for name in files:
            if not os.path.splitext(name)[1] in set(['.c', '.h']):
                continue

            parse_source(os.path.join(root, name))


def resolve_define_value(s):
    global defines

    while s in defines:
        s = defines[s]

    comment_pos = s.find('/*')
    if comment_pos >= 0:
        s = s[:comment_pos]

    return s.strip().strip('()')

def parse_array_count(var_name):
    brack_pos = var_name.find('[')
    if brack_pos >= 0:
        array_count = var_name[(brack_pos + 1):var_name.rfind(']')]
        var_name = var_name[:brack_pos]

        if array_count == '':
            array_count = 'max'
        else:
            array_count = resolve_define_value(array_count)
    else:
        array_count = '1'

    return var_name, array_count

def resolve_type_def(type_name):
    global typedefs

    while True:
        type_info = None
        if type_name in typedefs:
            type_info = typedefs[type_name]
        elif type_name.endswith('_t') and (type_name[:-2] + '_s') in typedefs:
            type_info = typedefs[type_name[:-2] + '_s']
        else:
            return type_name, ''

        struct_def, keyword = type_info
        if keyword != TYPEDEF_ALIAS:
            return keyword + ' ' + type_name, struct_def

        type_name = struct_def

def parse_struct(s):
    result = []

    for cur_line in s.split('\n'):
        if ';' in cur_line:
            cur_line = cur_line[:cur_line.find(';')]

        split_line = cur_line.split()
        if len(split_line) < 2:
            continue

        type_name = split_line[-2]
        var_name = split_line[-1]

        var_name, array_count = parse_array_count(var_name)

        type_name, struct_def = resolve_type_def(type_name)

        result.append(PersistBlockField(type_name, var_name, array_count,
            parse_struct(struct_def)))

    return result


def get_hex_const_value(s):
    s = resolve_define_value(s)
    if not s.startswith('0x'):
        sys.stderr.write('Error: id "%s" does not start with "0x"\n' % s)
        return None

    return binascii.unhexlify(s[2:])[::-1].decode('utf8')

def get_persist_block_name(const_name):
    for s in PERSIST_BLOCK_NAME_STRIP:
        const_name = const_name.replace(s, '')

    return const_name.strip('_').replace('__', '_')

def parse_persist_spec(block, format):
    cur_struct = ''
    for cur_line in format.split('\n'):
        cur_line = cur_line.strip().strip('*')
        if len(cur_line) == 0:
            continue

        if 'persist header:' in cur_line:
            if len(cur_struct) > 0:
                setattr(block, type, parse_struct(cur_struct))

            type = 'header'
            cur_struct = ''
            continue

        elif 'persist data:' in cur_line:
            if len(cur_struct) > 0:
                setattr(block, type, parse_struct(cur_struct))

            type = 'data'
            cur_struct = ''
            continue

        cur_struct += cur_line + '\n'

    if len(cur_struct) > 0:
        setattr(block, type, parse_struct(cur_struct))

def sort_persist_blocks(block_list):
    block_list.sort(key=lambda x: -len(x.children))

    for block in block_list:
        sort_persist_blocks(block.children)

def build_block_tree(file_type):
    global typedefs

    # create the main block (klpf header)
    header = parse_struct(typedefs[PERSIST_FILE_HEADER][0])

    main = PersistBlock(get_hex_const_value(PERSIST_FILE_MAGIC),
        PERSIST_CTX_MAIN)
    main.header = header[3:]     # remove the base block fields

    for block in file_type.blocks_by_name.values():
        for parent_id in block.parent_ids:
            # add the block to the parent's children
            if parent_id == PERSIST_CTX_MAIN:
                parent = main
            else:
                parent = file_type.blocks_by_name[parent_id]

            parent.children.append(block)

    # sort the blocks, output blocks with more children first
    result = [main]
    sort_persist_blocks(result)
    return result

def build_file_types():
    global specs

    file_types = {}
    for format, params, path, line_num in specs:
        block_id, ctx = params[:2]

        if not ctx.startswith(PERSIST_CTX_PREFIX):
            sys.stderr.write('Error: invalid prefix for ctx "%s"\n' % ctx)
            continue

        ctx = ctx[len(PERSIST_CTX_PREFIX):]
        ft_name, parent_id = ctx.split('_', 1)

        if not ft_name in file_types:
            ft_id = get_hex_const_value(PERSIST_TYPE_PREFIX + ft_name)
            file_type = PersistFileType(ft_id, ft_name)
            file_types[ft_name] = file_type
        else:
            file_type = file_types[ft_name]

        if parent_id in PERSIST_PARENT_ID_MAP:
            parent_id = PERSIST_PARENT_ID_MAP[parent_id]

        block = PersistBlock(get_hex_const_value(block_id),
            get_persist_block_name(block_id), parent_id, path, line_num)

        parse_persist_spec(block, format)

        if block.name in file_type.blocks_by_name:
            old_block = file_type.blocks_by_name[block.name]
            if block.json() != old_block.json():
                msg = ('Warning: duplicate block %s, file: %s' %
                    (block.name, file_type.id))
                msg += (', path1: %s:%s, path2: %s:%s\n' %
                    (old_block.path, old_block.line_num, path, line_num))
                sys.stderr.write(msg)
            else:
                old_block.parent_ids.add(parent_id)
        else:
            file_type.blocks_by_name[block.name] = block

    for file_type in file_types.values():
        file_type.children = build_block_tree(file_type)

    return file_types


base_dir = os.path.join(os.path.dirname(__file__), '../..')
for path in SOURCE_SCAN_PATHS:
    scan_source_dir(os.path.join(base_dir, path))
typedefs.update(PERSIST_EXTRA_TYPES)

file_types = build_file_types()
print(json.dumps(list(file_types.values()), indent=4, cls=JsonObjectEncoder))
