from test_base import *

EMPTY_TIMELINE_ID = 'empty'

# EXPECTED:
#   8 sec audio + video

def test(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    nl.timeline.create(NginxLiveTimeline(id=EMPTY_TIMELINE_ID, active=False, max_segments=1))

    st = KmpSendTimestamps()

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 8)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'index-svar1.m3u8', EMPTY_TIMELINE_ID))
    assertEquals(req.status_code, 400)
    logTracker.assertContains(b'no segments in timeline "empty"')
