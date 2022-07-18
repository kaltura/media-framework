from test_base import *

# EXPECTED:
#   var1:    av1, av1, av1, av1, av1 (30 sec each)
#   var2:    av2, av2, av2, av2, av2 (30 sec each)
#   var3:    av1, av1, av1, av2, av1 (30 sec each)
#   Note:    the transition from 1 to 2 can start one segment before the beginning of the 4th clip

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])
    sv3, sa3 = createVariant(nl, 'var3', [('v3', 'video'), ('a3', 'audio')])

    for i in range(1, 4):
        for mt in 'va':
            nl.track.update(NginxLiveTrack(id='%s%s' % (mt, i), group_id='%s' % i))


    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv3),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa3),
    ], st, 30, realtime=1)

    # var3 expected to choose either var1 or var2
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30, realtime=1)

    nl.track.update(NginxLiveTrack(id='v3', group_id='1'))
    nl.track.update(NginxLiveTrack(id='a3', group_id='1'))

    # var3 expected to choose var1
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30, realtime=1)

    nl.track.update(NginxLiveTrack(id='v3', group_id='2'))
    nl.track.update(NginxLiveTrack(id='a3', group_id='2'))

    # var3 expected to choose var2
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30, realtime=1)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv3),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa3),
    ], st, 30, realtime=1)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2, sv3, sa3])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)
