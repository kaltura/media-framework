from test_base import *

# EXPECTED:
#   26 sec audio + video + subtitle
#   1 sec ts gap
#   26 sec audio + video + subtitle
#   1 sec ts gap
#   26 sec audio + video + subtitle

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset main'], ['syncer', 'off'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, period_gap=90000))

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ss = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'en')

    pipes = [
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ss),
    ]

    kmpSendStreams(pipes, st, 25, realtime=10, waitForVideoKey=True)

    st.dts += 90000 * 60

    kmpSendStreams(pipes, st, 25, realtime=10, waitForVideoKey=True)

    st.dts += 90000 * 60

    kmpSendStreams(pipes, st, 25, realtime=10, waitForVideoKey=True)

    kmpSendEndOfStream([sv, sa, ss])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
