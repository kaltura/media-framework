from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_inactive_timeout', '100s'])


# EXPECTED:
#   3 sec audio + video
#   10 sec video only

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 3)

    kmpSendStreams([
        (rv, sv),
        (ra, KmpNullSender()),
    ], st, 10)

    kmpSendEndOfStream([sv])

    time.sleep(2)

    tracks = nl.track.getAll()
    assertEquals(tracks['a1']['pending_segments'], 1)
    assertGreaterThan(tracks['v1']['pending_segments'], 1)

    testLLDefaultStreams(channelId, __file__)

    kmpSendEndOfStream([sa])
