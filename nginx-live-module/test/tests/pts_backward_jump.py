from test_base import *

# EXPECTED:
#   27 sec video plays, then jumps to 37 sec with discontinuity

def updateConf(conf):
    getConfBlock(conf, ['live', 'preset main']).append(['syncer', 'off'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, realtime=False, waitForVideoKey=True)

    st.dts -= 10 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)
