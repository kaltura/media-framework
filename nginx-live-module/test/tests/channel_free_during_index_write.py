from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'store_s3_block dummy_bucket'])
    url = getConfParam(block, 'url')
    url[1] = 'http://127.0.0.1:8002'

    block = getConfBlock(conf, ['live'])
    for key in ['dvr_path', 'persist_setup_path']:
        delConfParam(block, key)

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

    time.sleep(.5)

    logTracker.assertContains('ngx_live_persist_channel_free: cancelling index write')

    cleanupStack.reset()
    time.sleep(1)
