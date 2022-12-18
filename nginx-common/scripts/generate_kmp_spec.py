import binascii
import json
import re
import os

STATE_INITIAL = 'initial'
STATE_STRUCT = 'struct'
STATE_UNION = 'union'
STATE_DEFINE = 'define'

TYPEDEF_ALIAS = 'alias'


PACKET_ID_PREFIX = 'KMP_PACKET_'
PACKET_HEADER_SPEC = '/* kmp header: '


defines = {}
typedefs = {}
packets = []
packet_ids = {}


def parse_source(path):
    global defines, typedefs, packets

    path = os.path.normpath(path)
    with open(path) as f:
        data = f.read()

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
            if packet_name != '':
                packets.append((packet_name, name))
                packet_name = ''
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
        if cur_line.strip().startswith(PACKET_ID_PREFIX):
            cur_line = cur_line.split('/*')[0].strip().rstrip(',')
            name, value = map(lambda x: x.strip(), cur_line.split('='))
            packet_ids[name] = value

        elif cur_line.startswith(PACKET_HEADER_SPEC):
            packet_name = cur_line[len(PACKET_HEADER_SPEC):].split()[0]

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

        result.append({
            'type': type_name,
            'name': var_name,
            'count': array_count,
            'children': parse_struct(struct_def),
        })

    return result

def get_hex_const_value(s):
    s = resolve_define_value(s)
    if not s.startswith('0x'):
        sys.stderr.write('Error: id "%s" does not start with "0x"\n' % s)
        return None

    return binascii.unhexlify(s[2:])[::-1].decode('utf8')


parse_source(os.path.join(os.path.dirname(__file__), '../src/ngx_live_kmp.h'))


blocks = []
for packet_name, type_name in packets:
    block = {
        'id': get_hex_const_value(packet_ids[packet_name]),
        'name': packet_name[len(PACKET_ID_PREFIX):],
        'header': parse_struct(typedefs[type_name][0]),
        'data': [],
        'children': [],
    }

    blocks.append(block)


packets = []
file_type = {'id': 'kmp', 'name': 'KMP', 'children': blocks}
print(json.dumps([file_type], indent=4))
