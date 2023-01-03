from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['http', 'server'], [['location', '/store/channel/test/filler'], [['proxy_pass', 'http://127.0.0.1:8002']]])

def test(channelId=CHANNEL_ID):
    TcpServer(8002, lambda s: nl.channel.delete(channelId))

    nl = setupChannelVideoAudio(channelId)

    assertHttpError(lambda: saveFiller(nl, channelId), 409)

    logTracker.assertContains(b'ngx_live_filler_write_handler: write failed 409')
    logTracker.assertContains(b'ngx_live_filler_write_cancel: cancelling write request')

    cleanupStack.reset()
    time.sleep(1)
