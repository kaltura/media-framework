from test_base import *

# EXPECTED:
#   30 sec audio + video + subtitle

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ss = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')

    sr = KmpSRTReader(TEST_VIDEO2_CC_ENG)

    cue = sr.cues[3]
    sr.cues[3] = (0, 1000, cue[2])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (sr, ss),
    ], st, 30)

    kmpSendEndOfStream([sv, sa, ss])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
