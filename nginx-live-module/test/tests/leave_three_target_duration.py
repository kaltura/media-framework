from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, max_segments=1, manifest_max_segments=1))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    testDefaultStreams(channelId, __file__)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    time.sleep(5)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'index-svar1.m3u8', TIMELINE_ID))
    assertEquals(req.status_code, 410)
