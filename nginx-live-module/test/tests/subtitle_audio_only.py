from test_base import *

# EXPECTED:
#   30 sec audio + subtitle

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sa, = createVariant(nl, 'var1', [('a1', 'audio')])
    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')
    ssEs = createSubtitleVariant(nl, 'sub2', 's2', 'Spanish', 'spa')

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ssEn),
        (KmpSRTReader(TEST_VIDEO2_CC_SPA), ssEs),
    ], st, 30)

    kmpSendEndOfStream([sa, ssEn, ssEs])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
