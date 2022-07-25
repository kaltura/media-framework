from test_base import *

# EXPECTED:
#   var1:    av1, av1, av2, av1, av1 (30 sec each)
#   var2:    av2, av2, av1, av2, av2 (30 sec each)
#   var3:    av1, av1, av1, av1, av1 (30 sec each)

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])
    sv3, sa3 = createVariant(nl, 'var3', [('v3', 'video'), ('a3', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv3),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa3),
    ], st, 30)

    # var3 expected to choose var1 (closer media info)
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30)

    # var3 expected to choose var2 (videos are swapped)
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa2),
    ], st, 30)

    # var3 expected to choose var1 (closer media info)
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv3),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa3),
    ], st, 30)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2, sv3, sa3])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
