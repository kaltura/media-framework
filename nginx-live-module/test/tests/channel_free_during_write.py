from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'store_s3_block dummy_bucket'])
    url = getConfParam(block, 'url')
    url[1] = 'http://127.0.0.1:8002'

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    TcpServer(8002, lambda s: nl.channel.delete(channelId))

    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', read=False))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=TIMELINE_ID, active=True))

    while True:
        try:
            nl.channel.get(channelId)
        except requests.exceptions.HTTPError, e:
            if e.response.status_code != 404:
                raise
            break

        time.sleep(.1)

    logTracker.assertContains('ngx_live_persist_setup_write_complete: write failed 409')

    cleanupStack.reset()
    time.sleep(1)
