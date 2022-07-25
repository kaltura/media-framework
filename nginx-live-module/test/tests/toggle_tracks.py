from test_base import *

# EXPECTED:
#   32 sec audio + 32 sec audio from the beginning

def setup(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])

    kmpSendStreams([
        (ra, sa1),
    ], st, 16, realtime=False)

    sa2.send(ra.mediaInfo)

    kmpSendStreams([
        (ra, sa2),
    ], st, 16, realtime=False)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2])

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    nl.setChannelId(channelId)

    sa1 = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'a1', 'audio', initialFrameId=1000000)
    sa2 = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'a2', 'audio', initialFrameId=1000000)

    st = KmpSendTimestamps()
    st.dts += 90000 * 60
    st.created += 90000 * 60

    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    kmpSendStreams([
        (ra, sa1),
    ], st, 16, realtime=False)

    sa2.send(ra.mediaInfo)

    kmpSendStreams([
        (ra, sa2),
    ], st, 16, realtime=False)

    kmpSendEndOfStream([sa1, sa2])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
