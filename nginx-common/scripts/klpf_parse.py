#!/usr/bin/env python
from optparse import OptionParser
import struct
import json
import zlib
import sys
import os

MAX_BLOCK_DEPTH = 5
LABEL_LEN = 2 * MAX_BLOCK_DEPTH + len('cccc header  ')

PERSIST_HEADER_SIZE_MASK       = 0x0fffffff
PERSIST_HEADER_FLAG_CONTAINER  = 0x10000000
PERSIST_HEADER_FLAG_INDEX      = 0x20000000
PERSIST_HEADER_FLAG_COMPRESSED = 0x40000000

FORMAT_KMP = 'kmp'
FORMAT_KLPF = 'klpf'

def print_hex(data, start, end, pos_format, label, next_label, label_len):
    pos = start
    while pos < end:
        next_pos = min(pos + 16, end)
        chunk = data[pos:next_pos]

        line = label + ' ' * (label_len - len(label))
        line += pos_format % pos

        raw = ''
        for ch in bytearray(chunk):
            line += '%02x ' % ch
            raw += chr(ch) if ch >= 32 and ch < 127 else '.'
        line += '   ' * (16 - len(chunk))
        print('%s %s' % (line, raw))

        pos = next_pos
        label = next_label


def print_hex_h264(data, start, end, pos_format, label, next_label, label_len):
    pos = start
    while pos + 5 <= end:
        size, nal_type = struct.unpack('>LB', data[pos:(pos + 5)])
        nal_type &= 0x1f

        cur_label = '%s nal(%s,%s)' % (label[:-5], nal_type, size)
        print_hex(data, pos, pos + 4 + size, pos_format, cur_label, next_label,
            label_len)
        pos += 4 + size

def add_block_specs(file_id, parent, result):
    for block in parent['children']:
        for type in ['header', 'data']:
            fields = block[type]
            if len(fields) == 0:
                continue

            # if fields contain a single 'u_char[max]' => assume binary data
            if len(fields) == 1 and fields[0]['type'] == 'u_char' and fields[0]['count'] == 'max':
                continue

            key = '_'.join([file_id, block['id'], type])
            result[key] = fields

        add_block_specs(file_id, block, result)

def parse_persist_spec(file_name):
    result = {}
    with open(file_name, 'rb') as f:
        spec = json.load(f)
        for ft in spec:
            add_block_specs(ft['id'], ft, result)

    return result

def parse_fields(fields, data, start, end, base_type, prefix, values, output):
    pos = start
    max_pos = pos
    max_bits = 0
    bit_field = 0

    for field in fields:
        type = field['type'].split(' ')[0]
        name = field['name']
        count = field['count']
        sub_fields = field['children']

        if base_type == 'union':
            max_pos = max(max_pos, pos)
            pos = start

        # get array count
        if count.isnumeric():
            count = int(count)
        elif count == 'max':
            count = -1
        elif count in values:
            count = values[count]
        elif prefix + count in values:
            count = values[prefix + count]
        else:
            print('Error: unknown count "%s"' % count)
            continue

        # handle strings/bit fields
        key = prefix + name
        value = None
        if type == 'u_char':
            if count < 0:
                count = end - pos
            value = data[pos:(pos + count)].decode('utf8').rstrip('\0')
            pos += count
        elif ':' in key:
            split_key = key.split(':')
            key = split_key[0]
            bit_count = int(split_key[1])

            value = 0
            for i in range(bit_count):
                if bit_field >= max_bits:
                    bits = struct.unpack('<L', data[pos:(pos + 4)])[0]
                    pos += 4
                    bit_field = 0
                    max_bits = 32

                value |= ((bits >> bit_field) & 1) << i
                bit_field += 1

        if value is not None:
            values[key] = value
            output.append((type, key, value))
            continue

        # handle arrays/structs/other types
        i = 0
        while True:
            if count < 0:
                if pos >= end:
                    break
            else:
                if i >= count:
                    break

            if count != 1:
                cur_key = '%s[%s]' % (key, i)
            else:
                cur_key = key

            value = None
            if type in set(['struct', 'union']):
                pos = parse_fields(sub_fields, data, pos, end, type,
                    cur_key + '.', values, output)
            elif type == 'uint16_t':
                value = struct.unpack('<H', data[pos:(pos + 2)])[0]
                pos += 2
            elif type == 'int32_t':
                value = struct.unpack('<l', data[pos:(pos + 4)])[0]
                pos += 4
            elif type == 'uint32_t':
                value = struct.unpack('<L', data[pos:(pos + 4)])[0]
                pos += 4
            elif type == 'int64_t':
                value = struct.unpack('<q', data[pos:(pos + 8)])[0]
                pos += 8
            elif type in set(['uint64_t', 'ngx_msec_t']):
                value = struct.unpack('<Q', data[pos:(pos + 8)])[0]
                pos += 8
            else:
                print('Error: unknown type %s' % type)
                sys.exit(1)

            if value is not None:
                values[cur_key] = value
                output.append((type, cur_key, value))

            i += 1

    return max(max_pos, pos)

last_codec_id = None
def print_fields(key, data, start, end, label_len):
    global last_codec_id

    if key.endswith('header'):
        start += BLOCK_HEADER_SIZE

    output = []
    end = parse_fields(spec[key], data, start, end, 'struct', '', {}, output)

    fmt = ''
    for i in range(2):
        fmt += '{:<%s}' % (max([len(str(x[i])) for x in output]) + 2)
    fmt += '{}'

    for type, name, value in output:
        print(' ' * label_len + fmt.format(type, name, value))
        if name == 'kmp.codec_id':
            last_codec_id = value

    return end

def print_data(key, data, start, end, pos_format, label, next_label,
    label_len):
    global spec

    if key == 'sgts_mdat_data' and last_codec_id == 7:
        print_hex_h264(data, start, end, pos_format, label, next_label,
            label_len)
    else:
        print_hex(data, start, end, pos_format, label, next_label, label_len)

    if key in spec:
        indent = ' ' * (len(next_label) - 2)
        print('')
        print(indent + '%s:' % key)
        parse_end = print_fields(key, data, start, end, label_len)
        print('')

        if parse_end < end:
            print_hex(data, parse_end, end, pos_format, indent + 'unparsed:',
                '', label_len)
            print('')

def print_blocks(data, start, end, pos_format, indent):
    global file_type

    title_indent = indent[:-1] + '-' if len(indent) > 0 else ''
    next_indent = indent + '| '

    pos = start
    while pos < end:
        if end - pos < BLOCK_HEADER_SIZE:
            print('Error: failed to read block header, pos: %s' % pos)
            return

        id = data[pos:(pos + 4)].decode('utf8')
        if options.format == FORMAT_KLPF:
            size, header_size = struct.unpack('<LL', data[(pos + 4):(pos + 12)])
        elif options.format == FORMAT_KMP:
            header_size, data_size = struct.unpack('<LL', data[(pos + 4):(pos + 12)])
            size = header_size + data_size

        if id == 'klpf':
            file_type = data[(pos + 20):(pos + 24)].decode('utf8')

        # print header
        header_flags = header_size & ~PERSIST_HEADER_SIZE_MASK
        header_size &= PERSIST_HEADER_SIZE_MASK
        if header_flags & PERSIST_HEADER_FLAG_INDEX:
            header_size = size

        if header_size < BLOCK_HEADER_SIZE:
            print('Error: header size too small, pos: %s' % pos)
            return

        data_pos = pos + header_size
        if data_pos > end:
            print('Error: header size overflow, pos: %s' % pos)
            return

        key = '_'.join([file_type, id, 'header'])
        print_data(key, data, pos, data_pos, pos_format,
            title_indent + id + ' header', next_indent, LABEL_LEN)

        # print data
        next_pos = pos + size
        if next_pos > end:
            print('Error: data size overflow, pos: %s' % pos)
            return

        key = '_'.join([file_type, id, 'data'])
        if header_flags & PERSIST_HEADER_FLAG_COMPRESSED:
            cur_data = zlib.decompress(data[data_pos:next_pos], 0)
            if header_flags & PERSIST_HEADER_FLAG_CONTAINER:
                print_blocks(cur_data, 0, len(cur_data), pos_format,
                    next_indent)
            else:
                print_data(key, cur_data, 0, len(cur_data), pos_format,
                    title_indent + id + ' data', next_indent, LABEL_LEN)
        else:
            if header_flags & PERSIST_HEADER_FLAG_CONTAINER:
                print_blocks(data, data_pos, next_pos, pos_format, next_indent)
            elif data_pos < next_pos:
                print_data(key, data, data_pos, next_pos, pos_format,
                    title_indent + id + ' data', next_indent, LABEL_LEN)

        pos = next_pos


parser = OptionParser(usage='%prog [OPTION]... INPUT_FILE',
    add_help_option=False)
parser.add_option('--help', help='display this help and exit', action='help')

parser.add_option('-s', '--spec-file', dest='spec', default=None,
    help='block specification file', metavar='SPEC_FILE')
parser.add_option('-f', '--format', dest='format', default=FORMAT_KLPF,
    help='input file format [default: %default]', metavar='FORMAT')

(options, args) = parser.parse_args()

if len(args) != 1:
    parser.error('expecting one argument')

if options.format == FORMAT_KLPF:
    BLOCK_HEADER_SIZE = 12
elif options.format == FORMAT_KMP:
    BLOCK_HEADER_SIZE = 16
    file_type = 'kmp'
else:
    parser.error('invalid format %s' % options.format)

if options.spec is not None:
    spec = parse_persist_spec(options.spec)
else:
    spec = {}

data = open(args[0], 'rb').read()

pos_chars = len('%x' % len(data))
pos_chars = (pos_chars + 1) / 2 * 2
pos_format = '%%0%dx: ' % pos_chars

print_blocks(data, 0, len(data), pos_format, '')
