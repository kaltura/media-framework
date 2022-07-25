from test_base import *

# EXPECTED:
#   var1: 25 sec video1 + audio1, 25 sec video2 + audio2, 16 sec video1 + audio1
#   var2: 25 sec video1 + audio1, 25 sec video2 + audio2, 16 sec video2 + audio2

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv1 = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra1 = KmpMediaFileReader(TEST_VIDEO1, 1)
    rv2 = KmpMediaFileReader(TEST_VIDEO2, 0)
    ra2 = KmpMediaFileReader(TEST_VIDEO2, 1)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv1, sv1),
        (ra1, sa1),
        (rv2, KmpNullSender()),
        (ra2, KmpNullSender()),
    ], st, 25, realtime=False)

    sv1.send(rv2.mediaInfo)
    sa1.send(ra2.mediaInfo)

    kmpSendStreams([
        (rv1, KmpNullSender()),
        (ra1, KmpNullSender()),
        (rv2, sv1),
        (ra2, sa1),
    ], st, 25, realtime=False)

    sv1.send(rv1.mediaInfo)
    sa1.send(ra1.mediaInfo)

    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])
    sv2.send(rv2.mediaInfo)
    sa2.send(ra2.mediaInfo)

    kmpSendStreams([
        (rv1, sv1),
        (ra1, sa1),
        (rv2, sv2),
        (ra2, sa2),
    ], st, 16, realtime=False)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)
