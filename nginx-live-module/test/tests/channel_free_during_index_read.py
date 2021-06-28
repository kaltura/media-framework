from test_base import *
import requests
import json

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append([['location', '/store/channel/test/index'], [['proxy_pass', 'http://127.0.0.1:8002']]])

    block = getConfBlock(conf, ['live'])
    block.append(['persist_cancel_read_if_empty', 'off'])

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    TcpServer(8002, lambda s: nl.channel.delete(channelId))

    multi = [
        {'method': 'POST', 'uri': '/channels', 'body': {'id': 'test', 'preset': 'main'}},
        {'method': 'POST', 'uri': '/channels/test/timelines', 'body': {'id': 'main', 'active': True}},
        {'method': 'POST', 'uri': '/channels/test/variants', 'body': {'id': '32'}},
        {'method': 'POST', 'uri': '/channels/test/tracks', 'body': {'id': 'a32@p', 'media_type': 'audio'}},
        {'method': 'POST', 'uri': '/channels/test/variants/32/tracks', 'body':{'id': 'a32@p', 'media_type': 'audio'}}
    ]

    req = requests.post(url=nl.url + '/multi', json=multi)
    resp = req.json()

    assert(len(resp) == 5)
    codes = map(lambda x: x['code'], resp)
    assert(codes == [409,] + [404,] * 4)

    logTracker.assertContains('ngx_live_persist_core_read_handler: read failed 409')

    cleanupStack.reset()
