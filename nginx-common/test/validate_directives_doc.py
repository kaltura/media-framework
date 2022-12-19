import os
import re


STATE_INITIAL = 'initial'
STATE_CMD = 'cmd'
STATE_ENUM = 'enum'
STATE_DISABLED_CMD = 'disabled'

CMD_START = 'static ngx_command_t  '
CMD_END = 'ngx_null_command'

ENUM_PREFIX = 'ngx_conf_enum_t  '
STATIC_ENUM_PREFIX = 'static ngx_conf_enum_t  '


CTX_MAP = {
    'NGX_MAIN_CONF': 'main',
    'NGX_HTTP_MAIN_CONF': 'http',
    'NGX_HTTP_SRV_CONF': 'server',
    'NGX_HTTP_LOC_CONF': 'location',
    'NGX_STREAM_MAIN_CONF': 'stream',
    'NGX_STREAM_SRV_CONF': 'server',
    'NGX_RTMP_MAIN_CONF': 'rtmp',
    'NGX_RTMP_SRV_CONF': 'server',
    'NGX_RTMP_APP_CONF': 'application',
    'NGX_LIVE_MAIN_CONF': 'live',
    'NGX_LIVE_PRESET_CONF': 'preset',
}

DIRECTIVE_SYNTAX_MAP = {
    'ngx_conf_set_msec_slot': ['msec'],
    'ngx_conf_set_num_slot': ['num', 'percent', 'level'],
    'ngx_conf_set_size_slot': ['size'],
    'ngx_conf_set_flag_slot': ['on | off'],
    'ngx_http_call_url_slot': ['url'],
    'ngx_conf_set_str_slot': ['str', 'path', 'name', 'key'],
    'ngx_conf_set_sec_slot': ['sec'],
    'ngx_conf_set_keyval_slot': ['name value'],
}


DOC_TEMPLATE = '''#### %s
* **syntax**: `%s`
* **default**: ``
* **context**: %s

XXX
'''


enums = {}

def parse_source(path, out):
    path = os.path.normpath(path)
    with open(path) as f:
        data = f.read()
    line_num = 0

    state = STATE_INITIAL
    block = None
    for cur_line in data.split('\n'):
        line_num += 1

        if state == STATE_INITIAL:
            if cur_line.startswith(CMD_START):
                state = STATE_CMD
            elif cur_line.startswith(ENUM_PREFIX):
                enum_name = cur_line[len(ENUM_PREFIX):].split('[')[0].strip()
                values = []
                enums[enum_name] = values
                state = STATE_ENUM
            elif cur_line.startswith(STATIC_ENUM_PREFIX):
                enum_name = cur_line[len(STATIC_ENUM_PREFIX):].split('[')[0].strip()
                values = []
                enums[enum_name] = values
                state = STATE_ENUM
            continue

        elif state == STATE_ENUM:
            if cur_line.startswith('};'):
                state = STATE_INITIAL
            elif '"' in cur_line:
                values.append(cur_line.split('"')[1])
            continue

        elif state == STATE_DISABLED_CMD:
            if cur_line.startswith('#endif'):
                state = STATE_CMD
            continue

        # state == STATE_CMD

        if CMD_END in cur_line:
            state = STATE_INITIAL
            continue

        if cur_line.startswith('#if 0'):
            state = STATE_DISABLED_CMD
            continue

        if '{' in cur_line:
            block = cur_line
        elif '}' in cur_line:
            block += cur_line
            block = block[(block.find('{') + 1):block.rfind('}')]
            fields = [x.strip() for x in block.split(',')]

            cmd_name = fields[0].split('"')[1]
            if fields[3] != '0':
                module_type = fields[3].split('_')[1]
            else:
                module_type = fields[1].split('_')[1]

            if cmd_name in out:
                prev = out[cmd_name]
                if prev[0] == module_type:
                    print('Warning: duplicate directive \"%s\", in %s:%s' % (cmd_name, path, line_num))
                prev_fields = prev[3]
                prev_fields[1] += '|' + fields[1]
            else:
                out[cmd_name] = (module_type, path, line_num, fields)

            block = None
        elif block is not None:
            block += cur_line

def scan_source_dir(top, out):
    for root, _, files in os.walk(top):
        for name in files:
            if not os.path.splitext(name)[1] in set(['.c', '.h']):
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

    cmd_level = -1
    for cur_line in data.split('\n'):
        line_num += 1

        if cur_line.startswith('* **'):
            name, value = cur_line[len('* **'):].split('**: ')
            value = value.strip()
            attrs[name] = value

        if not cur_line.startswith('#'):
            continue

        level = len(re.match('^#*', cur_line).group())

        if 'directives' in cur_line.lower():
            if cmd_level < 0:
                cmd_level = level
            continue

        if cmd_level < 0:
            continue

        if level <= cmd_level:
            cmd_level = -1
            attrs = {}
            continue

        attrs = {}
        cmd_name = cur_line.split()[1]
        if cmd_name in out:
            print('Warning: duplicate directive \"%s\", in %s:%s' % (cmd_name, path, line_num))
        out[cmd_name] = (path, line_num, attrs)

def get_command_ctx(flags):
    ctx = []
    for cur in flags.split('|'):
        if cur in CTX_MAP:
            ctx.append('`%s`' % CTX_MAP[cur])
    return ', '.join(ctx)

def print_undoc_commands(cmds):
    last_path = None
    for path, line, fields, cmd in cmds:
        if path != last_path:
            print('### %s Directives\n' % os.path.basename(path))
            last_path = path

        print(DOC_TEMPLATE % (cmd, cmd, get_command_ctx(fields[1])))

def validate_syntax_args(cmd_name, syntax, handler, post):
    if handler == 'ngx_conf_set_enum_slot':
        values = enums[post.lstrip('&')]
        expected = ' | '.join(values)
        if syntax != expected:
            print('Error: invalid syntax for %s, expected: %s, got: %s' % (cmd_name, expected, syntax))
        return

    if 'complex_value' in handler:
        if not syntax.endswith('expr'):
            print('Error: invalid syntax for %s, expected: expr, got: %s' % (cmd_name, syntax))
        return

    if cmd_name.endswith('hash_max_size') or cmd_name.endswith('hash_bucket_size'):
        expected = ['size']
    elif handler in DIRECTIVE_SYNTAX_MAP:
        expected = DIRECTIVE_SYNTAX_MAP[handler]
    else:
        return

    if syntax not in expected:
        print('Error: invalid syntax for %s, expected: %s, got: %s' % (cmd_name, expected, syntax))


base_dir = os.path.join(os.path.dirname(__file__), '../..')
base_dir = os.path.normpath(base_dir)

module_list = ['nginx-common', 'nginx-kmp-in-module', 'nginx-kmp-out-module']

for cur_file in os.listdir(base_dir):
    if cur_file.startswith('nginx') and cur_file not in module_list:
        module_list.append(cur_file)

for module in module_list:

    print('\n%s\n%s' % (module, '-' * len(module)))
    module_base = os.path.join(base_dir, module)
    readme_path = os.path.join(module_base, 'README.md')

    src_cmds = {}
    scan_source_dir(module_base, src_cmds)

    doc_cmds = {}
    if os.path.isfile(readme_path):
        parse_readme(readme_path, doc_cmds)

    undoc_cmds = set(src_cmds) - set(doc_cmds)
    non_exist_cmds = set(doc_cmds) - set(src_cmds)

    print('Info: ok, %s documented directives' % len(doc_cmds))

    if len(undoc_cmds) > 0:
        print('Error: undocumented directives: %s' % undoc_cmds)
        print_undoc_commands(sorted([src_cmds[cmd][1:] + (cmd,) for cmd in undoc_cmds]))

    if len(non_exist_cmds) > 0:
        print('Error: directives missing from src: %s' % non_exist_cmds)

    for cmd_name in set(doc_cmds).intersection(set(src_cmds)):
        doc_attrs = doc_cmds[cmd_name][2]
        src_fields = src_cmds[cmd_name][3]

        exp_ctx = get_command_ctx(src_fields[1])
        doc_ctx = doc_attrs['context']
        if exp_ctx != '' and exp_ctx != doc_ctx.replace('stream/server', 'server'):
            print('Error: invalid context for %s, expected: %s, got: %s' % (cmd_name, exp_ctx, doc_ctx))

        doc_syntax = doc_attrs['syntax'].strip('`')

        if 'NGX_CONF_BLOCK' in src_fields[1]:
            if not doc_syntax.endswith(' { ... }'):
                print('Error: syntax for %s missing block' % cmd_name)
                continue
            doc_syntax = doc_syntax[:-len(' { ... }')]
        else:
            if not doc_syntax.endswith(';'):
                print('Error: syntax for %s missing semicolon' % cmd_name)
                continue
            doc_syntax = doc_syntax[:-1]

        if not doc_syntax.startswith(cmd_name):
            print('Error: invalid syntax for %s: %s' % (cmd_name, doc_syntax))
            continue

        doc_syntax = doc_syntax[(len(cmd_name) + 1):]
        validate_syntax_args(cmd_name, doc_syntax, src_fields[2], src_fields[-1])
