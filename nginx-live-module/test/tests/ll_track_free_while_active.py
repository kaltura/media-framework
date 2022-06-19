from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_close_segment_delay', '0'])

# EXPECTED:
#   20 sec video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    nl.track.delete('a1')

    kmpSendStreams([
        (rv, sv),
    ], st, 10)

    kmpSendEndOfStream([sv])
    sa.close()

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))
    testLLDefaultStreams(channelId, __file__)
