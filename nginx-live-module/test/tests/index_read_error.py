from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append([['location', '/dvr/channel/test/index'], [['return', '400']]])

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    assertHttpError(
        lambda: nl.channel.create(NginxLiveChannel(id=channelId, preset='main')), 502)
    assertHttpError(
        lambda: nl.channel.get(channelId), 404)

    logTracker.assertContains('ngx_live_store_http_read_finished: request failed 400')
    logTracker.assertContains('ngx_live_persist_read_handler: read failed 502, file: 1')