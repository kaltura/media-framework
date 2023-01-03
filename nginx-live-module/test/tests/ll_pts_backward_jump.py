from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['syncer', 'off'])

# EXPECTED:
#   10 sec audio + video, then jump to sec ~16 and plays until 20

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 9.8, waitForVideoKey=True)

    st.dts -= 5 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendEndOfStream([sv, sa])

    time.sleep(5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_add_frame: enabling split due to pts backward jump')
    logTracker.assertContains(b'ngx_live_lls_track_get_pending_index: disposing frame with old pts')
