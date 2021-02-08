from test_base import *

# EXPECTED:
#   26 sec audio only
#   26 sec audio + video
#   26 sec video only

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sa = createTrack(nl, 'a1', 'audio', VARIANT_ID)

    kmpSendStreams([
        (rv, KmpNullSender()),
        (ra, sa),
    ], st, 25, realtime=False, waitForVideoKey=True)

    sv = createTrack(nl, 'v1', 'video', VARIANT_ID)
    sv.send(rv.mediaInfo)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=False)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 25, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)
