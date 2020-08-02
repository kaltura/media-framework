from test_base import *
import urllib
import select
import ctypes
import time

LONG_TEST = 1

# test options
DISABLE_DVR = False
BLOCKING_SEGMENT_REQUEST = False
WAIT_ACKS = False
MEDIA_INFO_CHANGE = False
NO_TRUNCATE = False


# Note: need to compile the module in release, otherwise the tests will take a long time

# Test matrix:

# params         result                                         error log
# NT+MI+WA     = memory limit exceeded after 220k segments/3m, 'cancelling write request', 'write failed', 'truncat', 'aborting write', 'exceeds limit'
# NT+WA        = memory limit exceeded after 4m segments/26m,  'cancelling write request', 'write failed', 'truncat', 'aborting write', 'exceeds limit'
# NT+MI+WA+DD  = memory limit exceeded after 220k segments/2m, 'truncat'
# NT+WA+DD     = memory limit exceeded after 4m segments/15m,  'truncat'
# MI+WA        = runs forever,                                 'cancelling write request', 'write failed', 'truncat', 'exceeds limit'
# WA           = runs forever,                                 'cancelling write request', 'write failed', 'truncat', 'exceeds limit'
# MI+WA+DD     = runs forever,                                 'truncat'
# WA+DD        = runs forever,                                 'truncat'
# BSR+MI+WA    = runs forever,                                 'request cleaned up', 'cancelling write request', 'write failed', 'truncat'
# BSR+MI+WA+DD = runs forever,                                 'request cleaned up', 'truncat'
# MI           = may fail on pending frame limit,              'cancelling write request', 'write failed', 'truncat', 'exceeds limit'
#              = may fail on pending frame limit,              'cancelling write request', 'write failed', 'truncat', 'exceeds limit'
# MI+DD        = may fail on pending frame limit,              'truncat'
# DD           = may fail on pending frame limit,              'truncat'


def updateConf(conf):
    # change error log severity
    errorLog = getConfParam(conf, 'error_log')
    errorLog[1] = errorLog[1].split(' ')[0] + ' notice'

    if DISABLE_DVR:
        block = getConfBlock(conf, ['live'])
        for key in ['dvr_path', 'persist_setup_path', 'persist_index_path', 'persist_delta_path']:
            delConfParam(block, key)

    if BLOCKING_SEGMENT_REQUEST:
        preset = getConfBlock(conf, ['live', 'preset main'])
        preset.append(['segmenter_duration','10s'])

        http = getConfBlock(conf, ['http'])
        http.append(['client_max_body_size','64m'])

class KmpMemorySender(object):
    def __init__(self):
        self.buf = ''
        self.name = 'mem'

    def send(self, data):
        self.buf += data

    def recv(self, bufsize):
        return ''

    def setsockopt(self, level, optname, value):
        pass

class SendBuffer(object):
    def __init__(self, data, size):
        self.data = data
        self.size = size
        self.pos = 0

    def active(self):
        return self.pos < self.size

    def left(self):
        return self.data[self.pos:self.size]

    def sent(self, size):
        self.pos += size

    @staticmethod
    def sendRecv(socks):
        while True:
            wfds = filter(lambda s: socks[s].active(), socks)
            if len(wfds) == 0:
                break
            rfds = socks.keys()
            readable, writable, exceptional = select.select(rfds, wfds, rfds, 0)
            for fd in readable:
                fd.recv(1024)    # ignore acks
            for fd in writable:
                cur = socks[fd]
                sent = fd.send(cur.left())
                cur.sent(sent)

class KmpBuffer(object):
    def __init__(self, data):
        self.data = ctypes.create_string_buffer(data)
        self.dataLen = len(data)
        self.frames = []

        curPos = 0
        while curPos < self.dataLen:
            type, header_size, data_size, reserved = kmpGetHeader(data[curPos:])
            if type != KMP_PACKET_FRAME:
                curPos += header_size + data_size
                continue

            created, dts, _, _ = kmpGetFrameHeader(data[curPos:])
            self.frames.append((curPos + KMP_PACKET_HEADER_SIZE, created, dts))

            curPos += header_size + data_size

    def getFrameCount(self):
        return len(self.frames)

    def getBuffer(self, shift):
        for pos, created, dts in self.frames:
            self.data[pos:(pos + 16)] = struct.pack('<qq', created + shift, dts + shift)
        return SendBuffer(self.data.raw, self.dataLen)

def sendBlockingSegmentRequest(channelId):
    global ds        # leave the socket connected

    # get the last segment file name
    index = urllib.urlopen(getStreamUrl(channelId, 'hls-fmp4', 'index-svar1.m3u8')).read()
    maxBitrate = 0
    segmentName = None
    for curLine in index.split('\n'):
        curLine = curLine.strip()
        if len(curLine) == 0:
            continue
        if curLine.startswith('#EXT-X-BITRATE:'):
            bitrate = int(curLine[len('#EXT-X-BITRATE:'):])
        if not curLine.startswith('#') and bitrate >= maxBitrate:
            segmentName = curLine.strip()
            maxBitrate = bitrate

    if segmentName is None:
        return

    # send a request for the segment without receiving
    req = '''GET /hls-fmp4/test/tl/main/%s HTTP/1.1
User-Agent: curl/7.35.0
Host: %s:%s
Accept: */*

'''
    req = req.replace('\r\n', '\n').replace('\n', '\r\n')
    req = req % (segmentName, NGINX_LIVE_HOST, NGINX_LIVE_PORT)

    ds = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ds.connect((NGINX_LIVE_HOST, NGINX_LIVE_PORT))
    ds.send(req)

class WaitAckSender(object):
    def __init__(self, s):
        self.s = s
        self.sentFrames = 0
        self.ackedFrames = 0

    def send(self, buf, frames):
        self.s.send(buf)
        self.sentFrames += frames
        while self.sentFrames > self.ackedFrames + 4 * 1024:
            header = self.s.recv(KMP_PACKET_HEADER_SIZE)
            type, header_size, data_size, reserved = kmpGetHeader(header)
            if type != KMP_PACKET_ACK_FRAMES:
                continue
            data = self.s.recv(header_size + data_size)
            frameId, offset = struct.unpack('<qL', data[:12])
            self.ackedFrames = frameId

def test(channelId=CHANNEL_ID):
    # print the params
    params = [
        'DISABLE_DVR',
        'BLOCKING_SEGMENT_REQUEST',
        'WAIT_ACKS',
        'MEDIA_INFO_CHANGE',
        'NO_TRUNCATE',
    ]

    print '%s started' % time.ctime()
    for param in params:
        print '%s: %s' % (param, globals()[param])

    # prepare the buffers in memory
    if BLOCKING_SEGMENT_REQUEST:
        video1 = TEST_VIDEO_HIGH        # need large segments to make send block
    else:
        video1 = TEST_VIDEO1
    video2 = TEST_VIDEO2

    readers = [
        (KmpMediaFileReader(video1, 0), KmpMediaFileReader(video1, 1)),
    ]

    if MEDIA_INFO_CHANGE:
        readers.append((KmpMediaFileReader(video2, 0), KmpMediaFileReader(video2, 1)))

    buffers = []
    st = KmpSendTimestamps()
    for curReaders in readers:
        curSenders = [KmpMemorySender() for _ in xrange(len(curReaders))]
        kmpSendStreams(zip(curReaders, curSenders), st,  maxDuration=10, realtime=False, waitForVideoKey=True)
        buffers.append(map(lambda ms: KmpBuffer(ms.buf), curSenders))
        st.dts += 9000        # add some margin to avoid backward jumps due to different pts delay

    # setup the channel/variant/tracks
    nl = setupChannelTimeline(channelId)
    if NO_TRUNCATE:
        nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, no_truncate=True))
    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sockets = [sv.s, sa.s]

    # send
    shift = 0
    i = 0

    if WAIT_ACKS:
        waitAckSenders = map(WaitAckSender, sockets)

    while True:
        for curBuffers in buffers:
            if WAIT_ACKS:
                for buffer, sender in zip(curBuffers, waitAckSenders):
                    sender.send(buffer.getBuffer(shift).left(), buffer.getFrameCount())
            else:
                sendBufs = map(lambda s: s.getBuffer(shift), curBuffers)
                SendBuffer.sendRecv(dict(zip(sockets, sendBufs)))
                time.sleep(0.001)

        shift += st.dts

        i += 1
        if i % 20 == 0 and BLOCKING_SEGMENT_REQUEST:
            sendBlockingSegmentRequest(channelId)

    print 'sending eos'
    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))
