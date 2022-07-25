from test_base import *

# EXPECTED:
#   25 sec audio + video
#   25 sec video only
#   25 sec audio + video
#   25 sec audio only (video freeze)
#   25 sec audio + video

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=1)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 25, realtime=1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=1)

    kmpSendStreams([
        (rv, KmpNullSender()),
        (ra, sa),
    ], st, 25, realtime=1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 25, realtime=1)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
