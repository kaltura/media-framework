from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'store_s3_block dummy_bucket'])
    url = getConfParam(block, 'url')
    url[1] = 'http://127.0.0.1:8002'

    block = getConfBlock(conf, ['live'])
    delConfParam(block, 'persist_setup_path')

    block.append(['mem_limit', '16m'])
    block.append(['store_http_write_resp_timeout', '1000000'])

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

        if logTracker.contains('ngx_live_dvr_write_cancel: cancelling write request'):
            break

    time.sleep(1)
