from test_base import *

# EXPECTED:
#   10 sec audio + video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv1, sa1 = createVariant(nl, '''?>=<;:.,+*'() ''', [('v1', 'video'), ('a1', 'audio')])
    sv2, sa2 = createVariant(nl, '''&%$#"!_^\[]@~|{}`''', [('v2', 'video'), ('a2', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 10.5)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2])

    time.sleep(1)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
