from test_base import *

CHANNEL_UID_START = 0x34

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
        f.write('\0' * 8)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assert(req.status_code == 502)
    logTracker.assertContains('ngx_live_persist_media_read_parse_header: uid mismatch, actual: 0000000000000000')
