import struct
import sys
import os

MAX_BLOCK_DEPTH = 5
LABEL_LEN = 2 * MAX_BLOCK_DEPTH + len('cccc header  ')

PERSIST_HEADER_SIZE_MASK      = 0x0fffffff
PERSIST_HEADER_FLAG_CONTAINER = 0x10000000
PERSIST_HEADER_FLAG_INDEX     = 0x20000000

def format_hex(data, start, end, pos_format, label, next_label, label_len):
    result = ''

    pos = start
    while pos < end:
        next_pos = min(pos + 16, end)
        chunk = data[pos:next_pos]

        line = label + ' ' * (label_len - len(label))
        line += pos_format % pos

        raw = ''
        for ch in chunk:
            line += '%02x ' % ord(ch)
            raw += ch if ord(ch) >= 32 and ord(ch) < 127 else '.'
        line += '   ' * (16 - len(chunk))
        result += '%s %s\n' % (line, raw)

        pos = next_pos
        label = next_label

    return result[:-1]

def print_blocks(data, start, end, pos_format, indent):
    title_indent = indent[:-1] + '-' if len(indent) > 0 else ''
    next_indent = indent + '| '

    pos = start
    while pos < end:
        if end - pos < 12:
            print 'Error: failed to read block header, pos: %s' % pos
            return

        id = data[pos:(pos + 4)]
        size, header_size = struct.unpack('<LL', data[(pos + 4):(pos + 12)])

        # print header
        header_flags = header_size & ~PERSIST_HEADER_SIZE_MASK
        header_size &= PERSIST_HEADER_SIZE_MASK
        if header_flags & PERSIST_HEADER_FLAG_INDEX:
            header_size = size

        if header_size < 12:
            print 'Error: header size too small, pos: %s' % pos
            return

        data_pos = pos + header_size
        if data_pos > end:
            print 'Error: header size overflow, pos: %s' % pos
            return

        print format_hex(data, pos, data_pos, pos_format,
            title_indent + id + ' header', next_indent, LABEL_LEN)

        # print data
        next_pos = pos + size
        if next_pos > end:
            print 'Error: data size overflow, pos: %s' % pos
            return

        if header_flags & PERSIST_HEADER_FLAG_CONTAINER:
            print_blocks(data, data_pos, next_pos, pos_format, next_indent)
        elif data_pos < next_pos:
            print format_hex(data, data_pos, next_pos, pos_format,
                title_indent + id + ' data', next_indent, LABEL_LEN)

        pos = next_pos

if len(sys.argv) < 2:
    print 'Usage:\n\t%s <input file>' % os.path.basename(sys.argv[0])
    sys.exit(1)

data = file(sys.argv[1], 'rb').read()

pos_chars = len('%x' % len(data))
pos_chars = (pos_chars + 1) / 2 * 2
pos_format = '%%0%dx: ' % pos_chars

print_blocks(data, 0, len(data), pos_format, '')
