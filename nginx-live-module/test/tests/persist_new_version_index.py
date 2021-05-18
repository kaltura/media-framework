from test_base import *

KLPF_VERSION_OFFSET = 16

def updateConf(conf):
    getConfBlock(conf, ['live']).append(['persist_cancel_read_if_empty', 'off'])

def setup(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

def test(channelId=CHANNEL_ID):
    with open('/tmp/store/channel/test/index', 'rb+') as f:
        f.seek(KLPF_VERSION_OFFSET)
        f.write(struct.pack('<L', 9999999))

    nl = nginxLiveClient()
    assertHttpError(
        lambda: nl.channel.create(NginxLiveChannel(id=channelId, preset='main')), 503)

    logTracker.assertContains('ngx_persist_read_file_header: file has a newer version 9999999, type: sgix')
