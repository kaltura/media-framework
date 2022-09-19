import struct
import sys

KMP_PACKET_HEADER_SIZE  = 16

KMP_PACKET_FRAME                = 0x6d617266   # fram


def kmpGetHeader(data):
    return struct.unpack('<LLLL', data[:KMP_PACKET_HEADER_SIZE])

def kmpCreatePacket(type, header, data, reserved = 0):
    return struct.pack('<LLLL', type, KMP_PACKET_HEADER_SIZE + len(header), len(data), reserved) + header + data


class KmpReaderBase(object):
    def getPacketType(self):
        return self.packetType

    def getPacketData(self):
        return self.packetData

    def next(self):
        res = self.getPacketData()
        self.readPacket()
        return res


class KmpReader(KmpReaderBase):
    def __init__(self, input):
        self.input = input
        self.readPacket()

    def readPacket(self):
        self.packetType = None
        self.packetData = None

        header = self.input.read(KMP_PACKET_HEADER_SIZE)
        if len(header) < KMP_PACKET_HEADER_SIZE:
            return

        type, header_size, data_size, reserved = kmpGetHeader(header)
        size = header_size + data_size - KMP_PACKET_HEADER_SIZE
        data = self.input.read(size)
        if len(data) < size:
            return

        self.packetType = type
        self.packetData = header + data


def minimizeFrame(data):
    res = ''

    header = data[KMP_PACKET_HEADER_SIZE:40]
    pos = 40
    while pos < len(data):
        size = struct.unpack('>L', data[pos:(pos + 4)])[0]
        pos += 4

        nal = data[pos:(pos + size)]
        pos += size

        if ord(nal[0]) & 0x1f == 6:  # SEI
            res += struct.pack('>L', size) + nal

    return kmpCreatePacket(KMP_PACKET_FRAME, header, res)

_, inFile = sys.argv

kr = KmpReader(open(inFile, 'rb'))
while True:
    if kr.packetType is None:
        break
    if kr.packetType != KMP_PACKET_FRAME:
        sys.stdout.write(kr.packetData)
    else:
        sys.stdout.write(minimizeFrame(kr.packetData))
    kr.next()
