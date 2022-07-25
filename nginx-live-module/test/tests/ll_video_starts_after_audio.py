from test_base import *

# EXPECTED:
#   10 sec audio only
#   10 sec audio + video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, KmpNullSender()),
        (ra, sa),
    ], st, 9.8)

    sv.send(rv.mediaInfo)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendEndOfStream([sv, sa])

    time.sleep(5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testLLDefaultStreams(channelId, __file__)
