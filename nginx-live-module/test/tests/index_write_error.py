from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append(
        [['location', '/store/channel/test/index'],
            [[['limit_except', 'GET'],
                [['deny', 'all']]],
            ['lingering_timeout', '1']]])

    block = getConfBlock(conf, ['live', 'preset main'])
    block.append(['store_http_write_retries', '0'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    time.sleep(2)

    logTracker.assertContains('ngx_live_store_http_write_complete: request failed')
    logTracker.assertContains('ngx_live_persist_index_write_complete: write failed')
