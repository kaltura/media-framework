from test_base import *
from threading import Lock

def updateConf(conf):
    appendConfDirective(conf, ['http', 'server', 'location /store/'], [['if', '($request_method = PUT)'], [['proxy_pass', 'http://127.0.0.1:8002']]])

def storeServer(s):
    global lock

    header = s.recv(4096)
    uri = header.split(b' ')[1]
    base = os.path.basename(uri)
    if base == b'0':
        lock.acquire()
        lock.release()
    elif base not in [b'setup', b'index']:
        s.send(getHttpResponseRegular(status=b'500 Internal Server Error'))
        return

    path = '/tmp' + uri.decode('utf8')
    data = readRequestBody(s, header)
    writeFile(path, data)
    s.send(getHttpResponseRegular())

def test(channelId=CHANNEL_ID):
    global lock

    TcpServer(8002, storeServer)

    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, manifest_max_segments=3))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')])

    lock = Lock()
    lock.acquire()

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 4, realtime=False)

    rv = KmpMediaFileReader(TEST_VIDEO2, 0)
    ra = KmpMediaFileReader(TEST_VIDEO2, 1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, realtime=False)

    kmpSendEndOfStream([sv, sa])

    lock.release()

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)
