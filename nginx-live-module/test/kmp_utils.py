import subprocess
import struct
import socket
import time
import sys
import os


FILE_TO_KMP_BIN = 'file-to-kmp/file_to_kmp'
DEV_STDOUT = '/dev/stdout'
DEFAULT_CREATED = 1577836800 * 90000    # 2020/1/1

KMP_PACKET_CONNECT              = 0x74636e63   # cnct
KMP_PACKET_MEDIA_INFO           = 0x666e696d   # minf
KMP_PACKET_FRAME                = 0x6d617266   # fram
KMP_PACKET_END_OF_STREAM        = 0x74736f65   # eost

KMP_PACKET_ACK_FRAMES           = 0x666b6361   # ackf

KMP_MAX_CHANNEL_ID_LEN  = (32)
KMP_MAX_TRACK_ID_LEN    = (32)

KMP_PACKET_HEADER_SIZE  = 16

KMP_MEDIA_VIDEO = 0
KMP_MEDIA_AUDIO = 1

KMP_FRAME_FLAG_KEY = 0x01

KMP_FRAME_HEADER_SIZE = 24

VERBOSITY = 0


class KmpReaderBase(object):
    def getPacketType(self):
        return self.packetType

    def getPacketData(self):
        return self.packetData

    def next(self):
        res = self.packetData
        self.readPacket()
        return res

class KmpReader(KmpReaderBase):
    def __init__(self, input, name = ''):
        self.mediaInfo = None
        self.timescale = None
        self.input = input
        self.name = name
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
        if type == KMP_PACKET_MEDIA_INFO:
            self.mediaInfo = self.packetData
            self.timescale = struct.unpack('<L', data[8:12])[0]


class KmpFileReader(KmpReader):
    def __init__(self, inputFile):
        self.inputFile = inputFile
        super(KmpFileReader, self).__init__(file(inputFile, 'rb'), inputFile)

class KmpMediaFileReader(KmpReader):
    def __init__(self, inputFile, streamId, createdBase=DEFAULT_CREATED):
        fileToKmp = os.path.join(os.path.dirname(__file__), FILE_TO_KMP_BIN)
        if not os.path.isfile(fileToKmp):
            print 'Error: "%s" does not exist\nPlease compile it' % fileToKmp
            sys.exit(1)

        self.inputFile = inputFile
        self.streamId = streamId
        p = subprocess.Popen([
            fileToKmp,
            '-s%s' % streamId,
            '-c%s' % createdBase,
            inputFile,
            DEV_STDOUT], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        super(KmpMediaFileReader, self).__init__(p.stdout, '%s:%s' % (inputFile, streamId))

class KmpSendTimestamps:
    def __init__(self):
        self.dts = 0
        self.created = DEFAULT_CREATED

class KmpNullSender(object):
    def __init__(self):
        self.name = None

    def send(self, data):
        pass

    def recv(self, bufsize):
        return ''

class KmpTcpSender(object):
    def __init__(self, addr, channelId, trackId, mediaType, initialFrameId = 0, initialOffset = 0):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(addr)
        s.send(kmpConnectPacket(channelId, trackId, initialFrameId, initialOffset))
        # reduce send buffer size for audio
        if mediaType == 'audio':
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)

        self.s = s
        self.name = '%s/%s' % (channelId, trackId)

    def send(self, data):
        self.s.send(data)

    def recv(self, bufsize):
        return self.s.recv(bufsize)

    def setsockopt(self, level, optname, value):
        return self.s.setsockopt(level, optname, value)

class FilteredSender(object):
    def __init__(self, sender, filter):
        self.sender = sender
        self.name = sender.name
        self.filter = filter

    def send(self, data):
        if self.filter(data):
            self.sender.send(data)

class KmpTypeFilteredSender(FilteredSender):
    def __init__(self, sender, types):
        super(KmpTypeFilteredSender, self).__init__(sender, lambda data: struct.unpack('<L', data[:4])[0] in types)


def kmpGetHeader(data):
    return struct.unpack('<LLLL', data[:KMP_PACKET_HEADER_SIZE])

def kmpCreatePacket(type, header, data, reserved = 0):
    return struct.pack('<LLLL', type, KMP_PACKET_HEADER_SIZE + len(header), len(data), reserved) + header + data

def kmpConnectPacket(channelId, trackId, initialFrameId = 0, initialOffset = 0):
    header = (channelId + '\0' * (KMP_MAX_CHANNEL_ID_LEN - len(channelId)) +
        trackId + '\0' * (KMP_MAX_TRACK_ID_LEN - len(trackId)) +
        struct.pack('<QLL', initialFrameId, initialOffset, 0))
    return kmpCreatePacket(KMP_PACKET_CONNECT, header, '')

def kmpEndOfStreamPacket():
    return kmpCreatePacket(KMP_PACKET_END_OF_STREAM, '', '')

def kmpGetFrameHeader(data):
    return struct.unpack('<qqLL', data[KMP_PACKET_HEADER_SIZE:(KMP_PACKET_HEADER_SIZE + KMP_FRAME_HEADER_SIZE)])

def kmpSetFrameHeader(data, frame):
    return data[:KMP_PACKET_HEADER_SIZE] + struct.pack('<qqLL', *frame) + data[(KMP_PACKET_HEADER_SIZE + KMP_FRAME_HEADER_SIZE):]

def kmpPacketToStr(data):
    type, headerSize, dataSize, reserved = kmpGetHeader(data)
    data = data[KMP_PACKET_HEADER_SIZE:]
    result = '%s, hs=%d, ds=%s' % (struct.pack('<L', type), headerSize, dataSize)
    if type == KMP_PACKET_CONNECT:
        channelId = data[:KMP_MAX_CHANNEL_ID_LEN].rstrip('\0')
        data = data[KMP_MAX_CHANNEL_ID_LEN:]
        trackId = data[:KMP_MAX_TRACK_ID_LEN].rstrip('\0')
        data = data[KMP_MAX_TRACK_ID_LEN:]
        initialFrameId, initialOffset = struct.unpack('<QL', data[:12])
        result += ', channel=%s, track=%s, frameId=%d, offset=%d' % (channelId, trackId, initialFrameId, initialOffset)
    elif type == KMP_PACKET_MEDIA_INFO:
        mediaType, codecId, timescale, bitrate = struct.unpack('<LLLL', data[:16])
        data = data[16:]
        result += ', type=%d, codec=%d, bitrate=%d' % (mediaType, codecId, bitrate)
        if mediaType == KMP_MEDIA_VIDEO:
            width, height, frameRateNum, frameRateDenom = struct.unpack('<HHLL', data[:12])
            result += ', width=%d, height=%d, frameRate=%d/%d' % (width, height, frameRateNum, frameRateDenom)
        elif mediaType == KMP_MEDIA_AUDIO:
            channels, bitsPerSample, sampleRate = struct.unpack('<HHL', data[:8])
            result += ', channels=%d, bitsPerSample=%d, sampleRate=%d' % (channels, bitsPerSample, sampleRate)
    elif type == KMP_PACKET_FRAME:
        created, dts, flags, ptsDelay = struct.unpack('<qqLL', data[:24])
        result += ', created=%d, dts=%d, flags=0x%x, ptsDelay=%d' % (created, dts, flags, ptsDelay)
    return result

def kmpGetMinDtsPipe(pipes):
    minDts = None
    minPipe = None
    for pipe in pipes:
        reader, sender = pipe

        while reader.getPacketType() is not None and reader.getPacketType() != KMP_PACKET_FRAME:
            sender.send(reader.next())

        if reader.getPacketType() is None:
            continue

        created, dts, flags, ptsDelay = kmpGetFrameHeader(reader.getPacketData())
        if minDts is None or dts < minDts:
            minDts = dts
            minPipe = pipe

    return minPipe

def kmpSendStreams(pipes, base = KmpSendTimestamps(), maxDuration = 0, realtime = True, waitForVideoKey = False):
    startTime = time.time()
    startDts = None
    dtsOffset = None

    if VERBOSITY > 0:
        print 'sendStream started, streams=%s, duration=%s, realtime=%s, waitForVideoKey=%s' % (len(pipes), maxDuration, realtime, waitForVideoKey)

    while True:
        minPipe = kmpGetMinDtsPipe(pipes)
        if minPipe is None:
            break

        reader, sender = minPipe
        data = reader.getPacketData()

        created, dts, flags, ptsDelay = kmpGetFrameHeader(data)

        if startDts is None:
            startDts = dts

        dtsOffset = dts - startDts
        dtsOffsetSec = dtsOffset / float(reader.timescale)
        created = base.created + dtsOffset
        dts = base.dts + dtsOffset

        mediaType = struct.unpack('<L', reader.mediaInfo[16:20])[0]
        if maxDuration > 0 and dtsOffsetSec > maxDuration and (not waitForVideoKey or (mediaType == KMP_MEDIA_VIDEO and flags & KMP_FRAME_FLAG_KEY)):
            break

        if realtime:
            sleepTime = startTime + dtsOffsetSec - time.time()
            if sleepTime > 0:
                time.sleep(sleepTime)

        data = kmpSetFrameHeader(data, (created, dts, flags, ptsDelay))

        if VERBOSITY > 1 and sender.name is not None:
            print '%s --> %s, created=%d, dts=%d, flags=0x%x, ptsDelay=%d' % (reader.name, sender.name, created, dts, flags, ptsDelay)

        sender.send(data)
        reader.next()

    if dtsOffset is not None:
        base.dts += dtsOffset
        base.created += dtsOffset

def kmpSendEndOfStream(sockets):
    for s in sockets:
        s.send(kmpEndOfStreamPacket())

        # wait for disconnect
        while len(s.recv(128)):
            continue
