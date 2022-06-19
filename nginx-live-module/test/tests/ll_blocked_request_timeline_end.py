from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end=DEFAULT_CREATED + 7 * 90000))

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

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    code, headers, body = t.join()
    assert(code == 200)
    assert(body.rstrip().endswith('#EXT-X-ENDLIST'))

    logTracker.assertContains('ngx_live_timeline_update: end_list enabled, publishing timeline')
    logTracker.assertContains('ngx_live_notif_segment_publish_timeline: calling handler 0')
    assertBetween(float(headers['block-duration'][0]), 0.9, 1.1)
