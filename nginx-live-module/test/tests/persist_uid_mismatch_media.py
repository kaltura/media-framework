from test_base import *
import socket

# persist_opaque is set to $hostname
CHANNEL_UID_START = 0x38 + len(socket.gethostname() + ':0.1')
CHANNEL_UID_END = CHANNEL_UID_START + 8

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

    time.sleep(1)

    with open('/tmp/store/channel/test/bucket/0', 'rb+') as f:
        f.seek(CHANNEL_UID_START)
        f.write(b'\0' * 8)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assertEquals(req.status_code, 502)
    logTracker.assertContains(b'ngx_live_persist_media_serve_parse_header: uid mismatch, actual: 0000000000000000')
