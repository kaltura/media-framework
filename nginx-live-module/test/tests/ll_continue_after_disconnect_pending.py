from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_inactive_timeout', '100s'])
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_frame_process_delay', '3s'])

# EXPECTED:
#   20 sec audio + video, with some short glitch around 4 sec

def stream(nl, duration, eos):
    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)
    rs = KmpSRTReader(TEST_VIDEO1_CC_ENG)

    st = KmpSendTimestamps()

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ss = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
        (rs, ss),
    ], st, duration)

    if eos:
        kmpSendEndOfStream([sv, sa, ss])
    else:
        time.sleep(2)
        sv.close()
        sa.close()
        ss.close()

def test(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    stream(nl, 7, False)
    stream(nl, 20, True)

    time.sleep(5)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_track_dispose_all: disposing')
