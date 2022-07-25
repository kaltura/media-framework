from test_base import *

# EXPECTED:
#   46 sec video plays continuously

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 23)

    st.dts += 1000 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 23)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_syncer_add_frame: large inter-frame pts jump')
