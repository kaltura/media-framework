from test_base import *

# EXPECTED:
#   26 sec audio + video
#   1 sec ts gap
#   26 sec audio + video
#   1 sec ts gap
#   26 sec audio + video

def updateConf(conf):
    getConfBlock(conf, ['live', 'preset main']).append(['syncer', 'off'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, period_gap=90000))

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv = createTrack(nl, 'v1', 'video', VARIANT_ID)
    sa = createTrack(nl, 'a1', 'audio', VARIANT_ID)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=False, waitForVideoKey=True)

    st.dts += 90000 * 60

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=False, waitForVideoKey=True)

    st.dts += 90000 * 60

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=False, waitForVideoKey=True)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    testDefaultStreams(channelId, __file__)
