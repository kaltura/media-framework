import subprocess
import struct
import sys
import os

TEMP_FILE = 'parse_rtmp_packet.tmp'

class Stream:
    def __init__(self, d, pos = 0):
        self.d = d
        self.pos = pos

    def eof(self):
        return self.pos >= len(self.d)

    def get(self, n = 1):
        result = self.d[self.pos:(self.pos + n)]
        self.pos += n
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
    print('Usage:\n\t%s <input file>' % os.path.basename(__file__))
    sys.exit(1)

d = open(sys.argv[1], 'rb').read()
s = Stream(d, 0xc01)     # after handshake

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
        print('>START\ttype=%s\tmlen=%s\tcsid=%s\tmsid=%s' %
            (curCtx.type, curCtx.mlen, csid, curCtx.msid))

    curCtx.msg += s.get(curSize)

    print('\toffset=0x%x\tcsid=%s\tsize=%s\tleft=%s' %
        (startPos, csid, curSize, curCtx.mlen - len(curCtx.msg)))

    if len(curCtx.msg) < curCtx.mlen:
        continue

    print('>END\ttype=%s\tmlen=%s\tcsid=%s\tmsid=%s' %
        (curCtx.type, curCtx.mlen, csid, curCtx.msid))

    open(TEMP_FILE, 'wb').write(curCtx.msg)
    print()
    print(subprocess.check_output('xxd %s' % TEMP_FILE).decode('utf8'))

    if curCtx.type == 1:
        chunkSize = struct.unpack('>L', curCtx.msg)[0]
        print('\tchunk size changed to %s' % chunkSize)

    curCtx.msg = b''
