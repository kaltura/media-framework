from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_close_segment_delay', '0'])

# EXPECTED:
#   30 sec audio + video + subtitle

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')
    ssEs = createSubtitleVariant(nl, 'sub2', 's2', 'Spanish', 'spa')

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ssEn),
        (KmpSRTReader(TEST_VIDEO2_CC_SPA), ssEs),
    ], st, 30)

    kmpSendEndOfStream([sv, sa, ssEn, ssEs])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testLLDefaultStreams(channelId, __file__)
