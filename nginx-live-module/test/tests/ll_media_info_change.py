from test_base import *

# EXPECTED:
#   6 sec video + audio1
#   6 sec video + audio2

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra1 = KmpMediaFileReader(TEST_VIDEO1, 1)
    ra2 = KmpMediaFileReader(TEST_VIDEO2, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra1, sa),
        (ra2, KmpNullSender()),
    ], st, 6)

    sa.send(ra2.mediaInfo)

    kmpSendStreams([
        (rv, sv),
        (ra1, KmpNullSender()),
        (ra2, sa),
    ], st, 6)

    kmpSendEndOfStream([sv, sa])

    time.sleep(5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_add_frame: updating end target')
