from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append([['location', '/store/channel/__filler/filler'], [['proxy_pass', 'http://127.0.0.1:8002']]])

def test(channelId=CHANNEL_ID):
    TcpServer(8002, lambda s: nl.channel.delete(FILLER_CHANNEL_ID))

    nl = nginxLiveClient()
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id=channelId, preset='main', filler=getFiller())), 503)

    time.sleep(1)

    logTracker.assertContains('ngx_live_filler_read_handler: read failed 409')
    logTracker.assertContains('ngx_live_filler_ready_handler: notif failed -6')

    cleanupStack.reset()
    time.sleep(1)
