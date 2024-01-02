from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server', 'location /ksmp_proxy/'])
    proxyPass = getConfParam(block, 'proxy_pass')
    proxyPass[1] = 'http://127.0.0.1:8002/ksmp/'

    appendConfDirective(conf, ['http', 'server'], ['pckg_pass_codes', '404'])

def test(channelId=CHANNEL_ID):
    # by default status codes are mapped to 502
    for status in [b'400 Bad Request', b'410 Gone', b'500 Internal Server Error']:
        TcpServer(8002, lambda s: socketSendAndShutdown(s, getHttpResponseRegular(b'x', status)))
        logTracker.init()
        req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
        assertEquals(req.status_code, 502)
        logTracker.assertContains(b'ngx_http_pckg_core_post_handler: bad subrequest status %s' % status[:3])
        cleanupStack.reset()

    # 404 passed as-is
    TcpServer(8002, lambda s: socketSendAndShutdown(s, getHttpResponseRegular(b'x', b'404 Not Found')))
    logTracker.init()
    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assertEquals(req.status_code, 404)
    logTracker.assertContains(b'ngx_http_pckg_core_post_handler: bad subrequest status 404')
    cleanupStack.reset()
