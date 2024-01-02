from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_close_segment_delay', '0'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10.5)

    url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8?_HLS_msn=3&_HLS_part=0')
    t = HttpRequestThread(url)

    time.sleep(1)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 5)

    kmpSendEndOfStream([sv, sa])

    code, headers, body = t.join()
    assertEquals(code, 503)
    assertGreaterThan(float(headers['block-duration'][0]), 10)

    # the wait completes, but then starts again
    logTracker.assertContains(b'ngx_live_notif_segment_publish: calling handler 0')
