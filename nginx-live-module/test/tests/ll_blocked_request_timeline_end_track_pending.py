from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_inactive_timeout', '100s'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end=DEFAULT_CREATED + 15 * 90000))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 10)

    url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-a.m3u8?_HLS_msn=3&_HLS_part=0')
    t = HttpRequestThread(url)

    time.sleep(1)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    time.sleep(1)

    kmpSendEndOfStream([sv, sa])

    code, headers, body = t.join()
    assert(code == 200)
    assert(b'seg-4-svar1-a.m4s' in body)

    # the wait handler is first called when end list is enabled, but it blocks again because the track is pending
    logTracker.assertContains(b'ngx_live_timeline_update: end_list enabled, publishing timeline')
    logTracker.assertContains(b'ngx_live_notif_segment_publish_timeline: calling handler 0')
    logTracker.assertContains(b'ngx_live_notif_segment_publish: calling handler 0')
    assertBetween(float(headers['block-duration'][0]), 1.9, 2.1)
