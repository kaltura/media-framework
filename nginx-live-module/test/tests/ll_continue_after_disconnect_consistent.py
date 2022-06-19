from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_inactive_timeout', '100s'])

# EXPECTED:
#   continuous 20 sec audio + video

def stream(nl, duration, eos):
    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)
    st = KmpSendTimestamps()

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')], flags=KMP_CONNECT_FLAG_CONSISTENT)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, duration)

    if eos:
        kmpSendEndOfStream([sv, sa])
    else:
        time.sleep(2)
        sv.close()
        sa.close()

def test(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    stream(nl, 7, False)
    stream(nl, 20, True)

    time.sleep(1)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertNotContains('ngx_live_lls_track_flush_segment: index: 1')
    logTracker.assertNotContains('ngx_live_lls_track_dispose_all: disposing')
