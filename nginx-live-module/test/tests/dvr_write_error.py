from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server', 'location /store/'])
    delConfParam(block, 'dav_methods')
    appendConfDirective(conf, ['http', 'server', 'location /store/'], ['lingering_timeout', '1'])    # nginx waits this timeout for any request completed with special status

    block = getConfBlock(conf, ['live'])
    for key in ['persist_setup_path', 'persist_index_path', 'persist_delta_path']:
        delConfParam(block, key)
    appendConfDirective(conf, ['live'], ['store_http_write_retries', '0'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    try:
        kmpSendStreams([
            (rv, sv),
            (ra, sa),
        ], st, 30, realtime=False)
    except socket.error:
        pass

    time.sleep(2)
    logTracker.assertContains(b'ngx_live_persist_media_write_complete: write failed')
