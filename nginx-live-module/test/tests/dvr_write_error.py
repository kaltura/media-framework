from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server', 'location /store/'])
    delConfParam(block, 'dav_methods')
    block.append(['lingering_timeout', '1'])    # nginx waits this timeout for any request completed with special status

    block = getConfBlock(conf, ['live'])
    for key in ['persist_setup_path', 'persist_index_path', 'persist_delta_path']:
        delConfParam(block, key)
    block.append(['store_http_write_retries', '0'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    try:
        kmpSendStreams([
            (rv, sv),
            (ra, sa),
        ], st, 30, realtime=False)
    except socket.error:
        pass

    time.sleep(2)
    logTracker.assertContains('ngx_live_dvr_write_complete: write failed')
