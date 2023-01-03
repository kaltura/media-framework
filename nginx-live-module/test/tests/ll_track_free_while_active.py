from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_close_segment_delay', '0'])

# EXPECTED:
#   20 sec video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)
    rs = KmpSRTReader(TEST_VIDEO1_CC_ENG)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ss = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
        (rs, ss),
    ], st, 10)

    nl.track.delete('a1')

    kmpSendStreams([
        (rv, sv),
        (rs, ss),
    ], st, 10)

    kmpSendEndOfStream([sv, ss])
    sa.close()

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testLLDefaultStreams(channelId, __file__)
