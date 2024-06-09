from test_base import *

# EXPECTED:
#   16 sec first video + audio
#   2 sec first video, no audio
#   10 sec second video + audio

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO_HIGH, 0)
    ra = KmpMediaFileReader(TEST_VIDEO_HIGH, 1)

    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 17.5, realtime=5)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 2, realtime=5)

    kmpSendEndOfStream([sv, sa])

    time.sleep(2)

    initialFrameId = 1000000

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')], initialFrameId=initialFrameId)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10, realtime=5)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
