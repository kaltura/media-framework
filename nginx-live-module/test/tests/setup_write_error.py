from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server', 'location /store/'])
    block.append(['lingering_timeout', '1'])
    block.append(['return', '400'])

    block = getConfBlock(conf, ['live', 'preset main'])
    block.append(['store_http_write_retries', '0'])

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', read=False))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=TIMELINE_ID, active=True))

    time.sleep(4)     # setup timeout
    logTracker.assertContains('ngx_live_store_http_write_complete: request failed')
    logTracker.assertContains('ngx_live_persist_setup_write_complete: write failed')
