from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append([['location', '/dvr/channel/test/bucket/'], [['proxy_pass', 'http://127.0.0.1:8002']]])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    TcpServer(8002, lambda s: nl.channel.delete(channelId))

    try:
        kmpSendStreams([
            (rv, sv),
            (ra, sa),
        ], st, 30, realtime=False)
    except socket.error:
        pass

    time.sleep(1)

    logTracker.assertContains('ngx_live_dvr_write_cancel: cancelling write request')

    cleanupStack.reset()
    time.sleep(1)
