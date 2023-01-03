from test_base import *
import requests
import json

def updateConf(conf):
    appendConfDirective(conf, ['http', 'server'], [['location', '/store/channel/test/index'], [['proxy_pass', 'http://127.0.0.1:8002']]])
    appendConfDirective(conf, ['live'], ['persist_cancel_read_if_empty', 'off'])

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

    assertEquals(len(resp), 5)
    codes = list(map(lambda x: x['code'], resp))
    assertEquals(codes, [409,] + [404,] * 4)

    logTracker.assertContains(b'ngx_live_persist_core_read_handler: read failed 409')

    cleanupStack.reset()
