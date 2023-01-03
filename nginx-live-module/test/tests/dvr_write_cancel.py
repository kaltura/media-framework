from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['http', 'server'], [['location', '/store/channel/test/bucket/'], [['proxy_pass', 'http://127.0.0.1:8002']]])

    appendConfDirective(conf, ['live'], ['mem_limit', '16m'])
    appendConfDirective(conf, ['live'], ['store_http_write_resp_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    serverSocket = createTcpServer(8002)    # hang dvr write requests

    while True:
        rv = KmpMediaFileReader(TEST_VIDEO1, 0)
        ra = KmpMediaFileReader(TEST_VIDEO1, 1)

        try:
            kmpSendStreams([
                (rv, sv),
                (ra, sa),
            ], st, 30, realtime=False)
        except socket.error:
            pass

        if logTracker.contains(b'ngx_live_persist_media_write_cancel: cancelling write request'):
            break

    time.sleep(1)
