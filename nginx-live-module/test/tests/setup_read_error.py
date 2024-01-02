from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['http', 'server', 'location /store/'], ['return', '400'])

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    assertHttpError(
        lambda: nl.channel.create(NginxLiveChannel(id=channelId, preset='main')), 502)
    assertHttpError(
        lambda: nl.channel.get(channelId), 404)

    logTracker.assertContains(b'ngx_live_store_http_read_finished: request failed 400')
    logTracker.assertContains(b'ngx_live_persist_core_read_handler: read failed 502, path: /store/channel/test/setup')
