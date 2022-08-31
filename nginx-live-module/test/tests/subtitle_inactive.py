from test_base import *

# EXPECTED:
#   30 sec audio + video, subtitles only in the beginning

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    ss = createTrack(nl, 's1', 'subtitle')
    nl.variant.create(NginxLiveVariant(id='sub1', role='alternate', track_ids={'subtitle': 's1'}))

    sr = KmpSRTReader(TEST_VIDEO2_CC_ENG)
    sr.cues = sr.cues[:5]

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (sr, ss),
    ], st, 30)

    kmpSendEndOfStream([sv, sa])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
