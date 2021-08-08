from test_base import *

# EXPECTED:
#   10 sec audio + video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.channel.update(NginxLiveChannel(id=channelId, initial_segment_index=100))
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, max_segments=3, manifest_max_segments=3))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1-svar1.m4s'))
    assert(req.status_code == 400)
    logTracker.assertContains('segment 0 does not exist')

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-101-svar1.m4s'))
    assert(req.status_code == 410)
    logTracker.assertContains('segment 100 does not exist')

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-108-svar1.m4s'))
    assert(req.status_code == 200)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'seg-1000-svar1.m4s'))
    assert(req.status_code == 400)
    logTracker.assertContains('segment 999 does not exist')
