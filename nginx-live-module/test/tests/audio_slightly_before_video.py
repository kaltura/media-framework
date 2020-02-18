from test_base import *

# EXPECTED:
#   25 sec video + audio, starting from ~4 sec (the beginning is truncated because it's missing video)
#   25 sec video only

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
    ], st, 3, realtime=False, waitForVideoKey=True)

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
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    testDefaultStreams(channelId, __file__)
