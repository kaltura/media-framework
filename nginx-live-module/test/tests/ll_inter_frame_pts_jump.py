from test_base import *

# EXPECTED:
#   46 sec video + audio with a small glitch at 23

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

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

    time.sleep(2)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_syncer_add_frame: large inter-frame pts jump')
