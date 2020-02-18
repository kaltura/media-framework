from test_base import *

# EXPECTED:
#   var1:    av1, av1, av1, av1 (30 sec each)
#   var2:    av1, av2, av1, av2 (30 sec each)

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
    ], st, 30)

    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), KmpTypeFilteredSender(sv2, [KMP_PACKET_FRAME])),
        (KmpMediaFileReader(TEST_VIDEO2, 1), KmpTypeFilteredSender(sa2, [KMP_PACKET_FRAME])),
    ], st, 30)

    # wait for inactivity flush
    time.sleep(11)

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    testDefaultStreams(channelId, __file__)
