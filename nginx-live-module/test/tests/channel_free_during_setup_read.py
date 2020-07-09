from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'store_s3_block dummy_bucket'])
    url = getConfParam(block, 'url')
    url[1] = 'http://127.0.0.1:8002'

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    TcpServer(8002, lambda s: nl.channel.delete(channelId))
    try:
        nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
        assert(False)
    except requests.exceptions.HTTPError, e:
        if e.response.status_code != 409:
            raise

    logTracker.assertContains('ngx_live_persist_read_handler: read failed 409')

    cleanupStack.reset()
    time.sleep(1)
