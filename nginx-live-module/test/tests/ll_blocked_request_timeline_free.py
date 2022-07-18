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

    time.sleep(1)

    nl.timeline.delete(TIMELINE_ID)

    code = t.join()[0]
    assert(code == 502)

    logTracker.assertContains(b'ngx_live_notif_segment_publish_timeline: calling handler -6')
    logTracker.assertContains(b'ngx_http_pckg_core_post_handler: bad subrequest status 409')
