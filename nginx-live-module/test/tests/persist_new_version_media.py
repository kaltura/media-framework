from test_base import *

KLPF_VERSION_OFFSET = 16

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
        f.seek(KLPF_VERSION_OFFSET)
        f.write(struct.pack('<L', 9999999))

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assertEquals(req.status_code, 502)
    logTracker.assertContains(b'ngx_persist_read_file_header: ignoring new file, version: 9999999, type: sgts')
