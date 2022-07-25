from test_base import *

def updateConf(conf):
    getConfBlock(conf, ['live', 'preset ll']).append(['syncer', 'off'])

# EXPECTED:
#   20 sec audio + video, with some freeze around 10 sec

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

    st.dts += 100 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendEndOfStream([sv, sa])

    time.sleep(5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_add_frame: enabling split due to pts forward jump')
