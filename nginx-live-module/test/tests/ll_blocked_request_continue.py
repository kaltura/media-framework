from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_close_segment_delay', '0'])

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

    kmpSendEndOfStream([sv, sa])

    url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8?_HLS_msn=3&_HLS_part=0')
    t = HttpRequestThread(url)

    time.sleep(2)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')], initialFrameId=1000000)
    sv.send(rv.mediaInfo)
    sa.send(ra.mediaInfo)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 5)

    kmpSendEndOfStream([sv, sa])

    code, headers, body = t.join()
    assertEquals(code, 200)
    assertGreaterThan(float(headers['block-duration'][0]), 2)
    assert('part-5-1-svar1-v.m4s' in body)  # segment number 4 was skipped to align on persist bucket

    logTracker.assertContains('ngx_live_notif_segment_publish: calling handler 0')
