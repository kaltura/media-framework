from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 11)

    time.sleep(1)

    url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8?_HLS_msn=3&_HLS_part=0')
    t = HttpRequestThread(url)

    code = t.join()[0]
    assert(code == 503)

    logTracker.assertContains('ngx_http_live_ksmp_wait_write_handler: wait request timed out')
    logTracker.assertContains('ngx_http_pckg_core_post_handler: ksmp error')
