from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live'])
    for key in ['persist_setup_path', 'persist_index_path', 'persist_delta_path']:
        delConfParam(block, key)

    appendConfDirective(conf, ['live'], ['force_memory_segments', '5'])
    appendConfDirective(conf, ['http', 'server', 'location /store/'], [['if', '($request_method = GET)'], [['proxy_pass', 'http://127.0.0.1:8002']]])

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

    time.sleep(4)  # wait for dvr writes to complete

    TcpServer(8002, lambda s: nl.channel.delete(channelId))

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assertEquals(req.status_code, 502)
    logTracker.assertContains(b'ngx_live_persist_media_channel_free: detaching from channel')
