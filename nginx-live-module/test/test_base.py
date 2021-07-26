from nginx_live_client import *
from cleanup_stack import *
from kmp_utils import *
from threading import Thread
import manifest_utils
import errno
import os
import re

NGINX_LIVE_HOST = 'localhost'
NGINX_LIVE_PORT = 8001
NGINX_LIVE_URL = 'http://%s:%s' % (NGINX_LIVE_HOST, NGINX_LIVE_PORT)
NGINX_LIVE_API_URL = '%s/control' % NGINX_LIVE_URL
NGINX_LIVE_KMP_ADDR = (NGINX_LIVE_HOST, 6543)

NGINX_LOG_PATH = '/var/log/nginx/error.log'

TEST_VIDEO1 = 'video1.mp4'
TEST_VIDEO2 = 'video2.mp4'
TEST_VIDEO_HIGH = 'video-high.mp4'
TEST_AUDIO_MP3 = 'audio-mp3.mp4'

TEST_VIDEO_URLS = {
    TEST_VIDEO1: 'http://cdnapi.kaltura.com/p/2035982/playManifest/entryId/0_k13xaap6/flavorId/0_4c84uq72/format/download/a.mp4',
    TEST_VIDEO2: 'http://cdnapi.kaltura.com/p/2035982/playManifest/entryId/0_w4l3m87h/flavorId/0_vsu1xutk/format/download/a.mp4',
    TEST_VIDEO_HIGH: 'http://cdnapi.kaltura.com/p/2035982/playManifest/entryId/0_g0nj9w94/flavorId/0_0smocyms/format/download/a.mp4',
    TEST_AUDIO_MP3: 'http://cdnapi.kaltura.com/p/2035982/playManifest/entryId/0_tfb5x3j0/flavorId/0_i30q8rs2/format/download/a.mp4',
}

CHANNEL_ID = 'test'
TIMELINE_ID = 'main'
VARIANT_ID = 'var1'
FILLER_CHANNEL_ID = '__filler'
FILLER_PRESET = 'main'
FILLER_TIMELINE_ID = 'main'

def nginxLiveClient():
    return NginxLive(NGINX_LIVE_API_URL)

def getHttpResponseRegular(body = '', status = '200 OK', length = None, headers = {}):
    if length == None:
        length = len(body)
    headersStr = ''
    if len(headers) > 0:
        for curHeader in headers.items():
            headersStr +='%s: %s\r\n' % curHeader
    return 'HTTP/1.1 %s\r\nContent-Length: %s\r\n%s\r\n%s' % (status, length, headersStr, body)

def getHttpResponseChunked(body = '', status = '200 OK', length = None, headers = {}):
    if length == None:
        length = len(body)
    headersStr = ''
    if len(headers) > 0:
        for curHeader in headers.items():
            headersStr +='%s: %s\r\n' % curHeader
    return 'HTTP/1.1 %s\r\nTransfer-Encoding: Chunked\r\n%s\r\n%x\r\n%s\r\n0\r\n' % (status, headersStr, length, body)

def readRequestBody(s, header):
    headerEnd = header.find('\r\n\r\n') + 4
    body = header[headerEnd:]
    header = header[:headerEnd]
    contentLength = int(re.findall('Content-Length: (\d+)', header)[0])
    while len(body) < contentLength:
        body += s.recv(contentLength - len(body))
    return body

def writeFile(path, data):
    try:
        os.makedirs(os.path.dirname(path))
    except OSError as e:
        if errno.EEXIST != e.errno:
            raise
    with open(path, 'wb') as f:
        f.write(data)

def getFiller():
    return NginxLiveFiller(channel_id=FILLER_CHANNEL_ID, preset=FILLER_PRESET,
        timeline_id=FILLER_TIMELINE_ID)

def saveFiller(nl, channelId=FILLER_CHANNEL_ID):
    nl.channel.update(NginxLiveChannel(id=channelId,
        filler=NginxLiveFiller(save=True, timeline_id=FILLER_TIMELINE_ID)))

def setupChannelTimeline(channelId, timelineId=TIMELINE_ID, preset='main'):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset=preset))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=timelineId, active=True))
    return nl

def createTrack(nl, trackName, mediaType, varName=None):
    nl.track.create(NginxLiveTrack(id=trackName, media_type=mediaType))
    if varName is not None:
        nl.variant.addTrack(variantId=varName, trackId=trackName)
    return KmpTcpSender(NGINX_LIVE_KMP_ADDR, nl.channelId, trackName, mediaType)

def createVariant(nl, varName, tracks):
    nl.variant.create(NginxLiveVariant(id=varName))

    result = []
    for trackName, mediaType in tracks:
        result.append(createTrack(nl, trackName, mediaType, varName))
    return result

def setupChannelVideoAudio(channelId, duration=10, timelineId=TIMELINE_ID):
    nl = setupChannelTimeline(channelId, timelineId)
    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')])

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ], st, duration, realtime=False)

    kmpSendEndOfStream([sv, sa])

    return nl

def getConfBlock(c, path):
    for cur in c:
        key = cur[0]
        if not isinstance(key, list):
            continue
        if ' '.join(key) != path[0]:
            continue
        if len(path) == 1:
            return cur[1]
        return getConfBlock(cur[1], path[1:])

def getConfParam(c, key):
    for cur in c:
        if cur[0] == key:
            return cur

def delConfParam(c, key):
    for i in xrange(len(c) - 1, -1, -1):
        if c[i][0] == key:
            c.pop(i)

def testStream(url, basePath, streamName):
    splittedPath = os.path.split(basePath)
    fileName = os.path.splitext(splittedPath[1])[0] + '-%s.txt' % streamName
    filePath = os.path.join(splittedPath[0], 'ref', fileName)

    info = manifest_utils.getStreamInfo(url)
    info = info.replace('\r\n', '\n')
    if not os.path.isfile(filePath):
        print 'Info: saving stream, url: %s, file: %s' % (url, filePath)
        file(filePath, 'w').write(info)
        return

    expected = file(filePath, 'r').read()
    expected = expected.replace('\r\n', '\n')
    if expected == info:
        return

    newFilePath = filePath + '.new'
    file(newFilePath, 'w').write(info)
    print 'Error: stream does not match, url: %s, orig: %s, new: %s' % (url, filePath, newFilePath)

def getStreamUrl(channelId, prefix, suffix='', timelineId=TIMELINE_ID):
    if len(suffix) == 0 and prefix.startswith('hls'):
        suffix = 'master.m3u8'

    return NGINX_LIVE_URL + '/%s/%s/tl/%s/%s' % (prefix, channelId, timelineId, suffix)

def testDefaultStreams(channelId, basePath, timelineId=TIMELINE_ID):
    for prefix in ['hls-ts', 'hls-fmp4']:
        url = getStreamUrl(channelId, prefix, timelineId=timelineId)
        testStream(url, basePath, prefix)


def assertHttpError(func, status):
    try:
        func()
        assert(False)
    except requests.exceptions.HTTPError, e:
        if e.response.status_code != status:
            raise


### Log tracker - used to verify certain lines appear in nginx log
class LogTracker:
    def init(self):
        self.initialSize = os.path.getsize(NGINX_LOG_PATH)

    def contains(self, logLine):
        f = file(NGINX_LOG_PATH, 'rb')
        f.seek(self.initialSize, os.SEEK_SET)
        buffer = f.read()
        f.close()

        buffer = re.sub(r'\[emerg\] [^ ]+ bind\(\) to [^ ]+ failed', '', buffer)

        if type(logLine) == list:
            found = False
            for curLine in logLine:
                if curLine in buffer:
                    found = True
                    break
            return found
        else:
            return logLine in buffer

    def assertContains(self, logLine):
        assert(self.contains(logLine))

    def assertNotContains(self, logLine):
        assert(not self.contains(logLine))

    def assertNoCriticalErrors(self):
        self.assertNotContains(['[emerg]', '[alert]', '[crit]'])

logTracker = LogTracker()


### TCP server
def createTcpServer(port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)     # prevent Address already in use errors
    s.bind(('0.0.0.0', port))
    s.listen(5)
    cleanupStack.push(s.close)
    return s

class TcpServer(Thread):
    def __init__(self, port, callback):
        Thread.__init__(self)
        self.port = port
        self.callback = callback
        self.keepRunning = True
        self.serverSocket = createTcpServer(port)
        self.start()
        cleanupStack.push(self.stopServer)

    def run(self):
        while self.keepRunning:
            (clientsocket, address) = self.serverSocket.accept()
            if self.keepRunning:
                self.callback(clientsocket)
            clientsocket.close()

    def stopServer(self):
        self.keepRunning = False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(('127.0.0.1', self.port))     # release the accept call
        s.close()
        while self.isAlive():
            time.sleep(.1)
