from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_inactive_timeout', '100s'])

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

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    kmpSendEndOfStream([sv, sa])

    code, headers, body = t.join()
    assert(code == 200)
    assert(body.rstrip().endswith(b'#EXT-X-ENDLIST'))

    logTracker.assertContains(b'ngx_live_timeline_update_last_segment: end_list enabled, publishing timeline')
    assertBetween(float(headers['block-duration'][0]), 0.9, 1.1)
