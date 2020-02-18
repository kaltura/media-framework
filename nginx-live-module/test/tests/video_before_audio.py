from test_base import *

# EXPECTED:
#   26 sec video only
#   26 sec audio + video
#   26 sec audio only (video freeze)

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv = createTrack(nl, 'v1', 'video', VARIANT_ID)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 25, realtime=False, waitForVideoKey=True)

    sa = createTrack(nl, 'a1', 'audio', VARIANT_ID)
    sa.send(ra.mediaInfo)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=False)

    kmpSendStreams([
        (rv, KmpNullSender()),
        (ra, sa),
    ], st, 25, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    testDefaultStreams(channelId, __file__)
