from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_frame_process_delay', '0'])
    block.append(['ll_segmenter_close_segment_delay', '0'])

# EXPECTED:
#   54 sec video plays continuously
#   segment duration changes from 4 to 8

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, manifest_target_duration_segments=100))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, waitForVideoKey=True)

    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=8000))

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains('ngx_live_lls_channel_duration_changed: set to 8000')
