import struct
import sys
import os

def print_hex(data):
    result = ''
    indent = 10
    pos = 0
    while pos < len(data):
        next_pos = min(pos + 16, len(data))
        chunk = data[pos:next_pos]

        line = ' ' * indent + '%04x: ' % pos

        raw = ''
        for ch in bytearray(chunk):
            line += '%02x ' % ch
            raw += chr(ch) if ch >= 32 and ch < 127 else '.'
        line += '   ' * (16 - len(chunk))
        result += '%s %s\n' % (line, raw)

        pos = next_pos

    print(result)

class Stream:
    def __init__(self, files):
        self.files = files
        self.file_idx = 0
        self.f = None
        self.max = 0
        self.buf = b''
        self.pos = 0

    def read(self):
        while True:
            if self.f is not None:
                self.buf = self.f.read(102400)
                if len(self.buf) > 0:
                    return True

            if self.file_idx >= len(self.files):
                return False

            path = self.files[self.file_idx]
            self.f = open(path, 'rb')
            self.max = os.path.getsize(path)
            self.file_idx += 1

    def eof(self):
        return self.pos >= len(self.buf) and self.file_idx >= len(self.files) and self.f.tell() >= self.max

    def get(self, n = 1):
        result = b''
        while len(result) < n:
            if self.pos >= len(self.buf):
                if not self.read():
                    break
                self.pos = 0
            size = n - len(result)
            result += self.buf[self.pos:(self.pos + size)]
            self.pos += size
        return result

    def getBENum(self, n = 1):
        buf = self.get(n)
        buf = b'\0' * (4 - len(buf)) + buf
        return struct.unpack('>L', buf)[0]

    def getLENum(self, n = 1):
        buf = self.get(n)
        buf = buf + b'\0' * (4 - len(buf))
        return struct.unpack('<L', buf)[0]

class Csctx:
    def __init__(self):
        self.msg = b''
        self.msid = -1

if len(sys.argv) < 2:
    print('Usage:\n\t%s <input file1> [<input file2> ... ]' % os.path.basename(__file__))
    sys.exit(1)

s = Stream(sys.argv[1:])
s.get(0xc01)     # skip handshake

ctx = {}
chunkSize = 128

while not s.eof():
    startPos = s.pos

    val = s.getBENum(1)
    fmt = (val >> 6) & 0x03
    csid = val & 0x3f
    if csid == 0:
        csid = 64
        csid += s.getBENum(1)
    elif csid == 1:
        csid = 64
        csid += s.getBENum(1)
        csid += s.getBENum(1) * 256

    if csid not in ctx:
        ctx[csid] = Csctx()
    curCtx = ctx[csid]

    if fmt <= 2:
        curCtx.timestamp = s.getBENum(3)
        if fmt <= 1:
            curCtx.mlen = s.getBENum(3)
            curCtx.type = s.getBENum(1)
            if fmt == 0:
                curCtx.msid = s.getLENum(4)

        if curCtx.timestamp == 0xffffff:
            curCtx.timestamp = s.getBENum(4)

    messageLeft = curCtx.mlen - len(curCtx.msg)
    curSize = min(messageLeft, chunkSize)

    if curCtx.msg == b'':
        print('>START\ttype=%s\tmlen=%s\tcsid=%s\tmsid=%s\tts=%s' %
            (curCtx.type, curCtx.mlen, csid, curCtx.msid, curCtx.timestamp))

    curCtx.msg += s.get(curSize)

    print('\toffset=0x%x\tcsid=%s\tsize=%s\tleft=%s' %
        (startPos, csid, curSize, curCtx.mlen - len(curCtx.msg)))

    if len(curCtx.msg) < curCtx.mlen:
        continue

    print('>END\ttype=%s\tmlen=%s\tcsid=%s\tmsid=%s' %
        (curCtx.type, curCtx.mlen, csid, curCtx.msid))

    print('')
    print_hex(curCtx.msg)

    if curCtx.type == 1:
        chunkSize = struct.unpack('>L', curCtx.msg)[0]
        print('\tchunk size changed to %s' % chunkSize)

    curCtx.msg = b''
