from test_base import *

# EXPECTED:
#   plays 54 sec, small video glitch + loss of audio for a few sec in the middle

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset main'], ['syncer', 'off'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, realtime=False)

    st.dts -= 10 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 26, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_segmenter_frame_list_copy: invalid frame duration')
