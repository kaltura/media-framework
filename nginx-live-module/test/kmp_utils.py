from cleanup_stack import *
import subtitle_utils
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

KMP_MAX_CHANNEL_ID_LEN  = 32
KMP_MAX_TRACK_ID_LEN    = 32

KMP_CONNECT_FLAG_CONSISTENT = 0x01

KMP_PACKET_HEADER_SIZE  = 16

KMP_MEDIA_VIDEO = 0
KMP_MEDIA_AUDIO = 1
KMP_MEDIA_SUBTITLE = 2

KMP_FRAME_FLAG_KEY = 0x01

KMP_FRAME_HEADER_SIZE = 24

KMP_CODEC_SUBTITLE_WEBVTT = 2001

VERBOSITY = 0


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
        super(KmpFileReader, self).__init__(open(inputFile, 'rb'), inputFile)


class KmpMediaFileReader(KmpReader):
    def __init__(self, inputFile, streamId, createdBase=DEFAULT_CREATED):
        fileToKmp = os.path.join(os.path.dirname(__file__), FILE_TO_KMP_BIN)
        if not os.path.isfile(fileToKmp):
            print('Error: "%s" does not exist\nPlease compile it' % fileToKmp)
            sys.exit(1)

        self.inputFile = inputFile
        self.streamId = streamId
        self.p = subprocess.Popen([
            fileToKmp,
            '-s%s' % streamId,
            '-c%s' % createdBase,
            inputFile,
            DEV_STDOUT], stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True)
        super(KmpMediaFileReader, self).__init__(self.p.stdout, '%s:%s' % (inputFile, streamId))

        cleanupStack.push(lambda: self.close())

    def close(self):
        self.p.terminate()


class KmpMemoryReader(KmpReaderBase):
    def __init__(self, reader, duration):
        self.packets = []
        startDts = None
        while True:
            if reader.getPacketType() is None:
                break

            if reader.getPacketType() != KMP_PACKET_FRAME:
                self.packets.append(reader.next())
                continue

            data = reader.next()
            created, dts, flags, ptsDelay = kmpGetFrameHeader(data)

            if startDts is None:
                startDts = dts

            dtsOffsetSec = (dts - startDts) / float(reader.timescale)
            if dtsOffsetSec > duration:
                break

            self.packets.append(data)

        self.mediaInfo = reader.mediaInfo
        self.timescale = reader.timescale
        self.name = reader.name
        self.reset()

    def reset(self):
        self.index = 0
        self.readPacket()

    def readPacket(self):
        if self.index >= len(self.packets):
            self.packetType = None
            self.packetData = None
        else:
            self.packetData = self.packets[self.index]
            self.packetType = struct.unpack('<L', self.packetData[:4])[0]
            self.index += 1


class KmpSRTReader(KmpReaderBase):
    def __init__(self, inputFile, createdBase=DEFAULT_CREATED):
        self.name = inputFile

        with open(inputFile, 'rb') as f:
            self.cues = subtitle_utils.parseSRTCues(f.read())
        self.cueIndex = -1

        self.timescale = 90000
        self.createdBase = createdBase

        self.initMediaInfo()

        self.readPacket()

    def initMediaInfo(self):
        bitrate = 100
        extraData = 'WEBVTT'

        mediaInfo = struct.pack('<LLLL', KMP_MEDIA_SUBTITLE, KMP_CODEC_SUBTITLE_WEBVTT, self.timescale, bitrate) + '\0' * 16
        self.mediaInfo = kmpCreatePacket(KMP_PACKET_MEDIA_INFO, mediaInfo, extraData)

    @staticmethod
    def getVttcAtom(payload):
        payload = struct.pack('>L', 8 + len(payload)) + b'payl' + payload
        return struct.pack('>L', 8 + len(payload)) + b'vttc' + payload

    def readPacket(self):
        if self.cueIndex >= len(self.cues):
            self.packetType = None
            self.packetData = None
            return

        if self.cueIndex < 0:
            self.cueIndex = 0
            self.packetType = KMP_PACKET_MEDIA_INFO
            self.packetData = self.mediaInfo
            return

        start, end, body = self.cues[self.cueIndex]
        self.cueIndex += 1

        start = (start * self.timescale) // 1000
        end = (end * self.timescale) // 1000

        created = self.createdBase + start
        dts = start
        ptsDelay = end - start
        flags = 0

        header = struct.pack('<qqLl', created, dts, flags, ptsDelay)

        self.packetType = KMP_PACKET_FRAME
        self.packetData = kmpCreatePacket(self.packetType, header, self.getVttcAtom(body))


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
    def __init__(self, addr, channelId, trackId, mediaType, initialFrameId = 0, initialOffset = 0, flags = 0, data = b''):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(addr)
        s.send(kmpConnectPacket(channelId, trackId, initialFrameId, initialOffset, flags, data))
        # reduce send buffer size for audio
        if mediaType == 'audio':
            s.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 1024)

        self.s = s
        self.name = '%s/%s' % (channelId, trackId)

    def send(self, data):
        self.s.send(data)

    def recv(self, bufsize):
        return self.s.recv(bufsize)

    def close(self):
        return self.s.close()

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

def kmpConnectPacket(channelId, trackId, initialFrameId = 0, initialOffset = 0, flags = 0, data = b''):
    header = (channelId.encode('utf8') + b'\0' * (KMP_MAX_CHANNEL_ID_LEN - len(channelId)) +
        trackId.encode('utf8') + b'\0' * (KMP_MAX_TRACK_ID_LEN - len(trackId)) +
        struct.pack('<QQLL', initialFrameId, 0, initialOffset, flags))
    return kmpCreatePacket(KMP_PACKET_CONNECT, header, data)

def kmpEndOfStreamPacket():
    return kmpCreatePacket(KMP_PACKET_END_OF_STREAM, b'', b'')

def kmpGetFrameHeader(data):
    return struct.unpack('<qqLl', data[KMP_PACKET_HEADER_SIZE:(KMP_PACKET_HEADER_SIZE + KMP_FRAME_HEADER_SIZE)])

def kmpSetFrameHeader(data, frame):
    return data[:KMP_PACKET_HEADER_SIZE] + struct.pack('<qqLl', *frame) + data[(KMP_PACKET_HEADER_SIZE + KMP_FRAME_HEADER_SIZE):]

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
        created, dts, flags, ptsDelay = struct.unpack('<qqLl', data[:24])
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

def kmpSendStreams(pipes, base = KmpSendTimestamps(), maxDuration = 0, maxDts = 0, realtime = 4, waitForVideoKey = False):
    startTime = time.time()
    startDts = None
    dtsOffset = None
    lastProgress = None

    if VERBOSITY >= 2:
        print('sendStream started, streams=%s, duration=%s, realtime=%s, waitForVideoKey=%s' % (len(pipes), maxDuration, realtime, waitForVideoKey))

    if not realtime:
        realtime = 20

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

        if VERBOSITY == 1:
            if lastProgress is not None:
                sys.stdout.write('\b' * len(lastProgress))
            lastProgress = '%.2f' % dtsOffsetSec
            sys.stdout.write(lastProgress)
            sys.stdout.flush()

        mediaType = struct.unpack('<L', reader.mediaInfo[16:20])[0]
        if not waitForVideoKey or (mediaType == KMP_MEDIA_VIDEO and flags & KMP_FRAME_FLAG_KEY):
            if maxDuration > 0 and dtsOffsetSec > maxDuration:
                break
            if maxDts > 0 and dts >= maxDts:
                break

        created = base.created + dtsOffset
        dts = base.dts + dtsOffset

        sleepTime = dtsOffsetSec - (time.time() - startTime) * realtime
        if sleepTime > 0:
            time.sleep(sleepTime)

        data = kmpSetFrameHeader(data, (created, dts, flags, ptsDelay))

        if VERBOSITY >= 3 and sender.name is not None:
            print('%s --> %s, created=%d, dts=%d, flags=0x%x, ptsDelay=%d' % (reader.name, sender.name, created, dts, flags, ptsDelay))

        sender.send(data)
        reader.next()

    if dtsOffset is not None:
        base.dts += dtsOffset
        base.created += dtsOffset

    if VERBOSITY == 1:
        sys.stdout.write('\n')
        sys.stdout.flush()

def kmpSendEndOfStream(sockets):
    for s in sockets:
        s.send(kmpEndOfStreamPacket())

        # wait for disconnect
        while len(s.recv(128)):
            continue
