from test_base import *

# EXPECTED:
#   20 sec video

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, max_segments=5, manifest_max_segments=5))

    rv1 = KmpMediaFileReader(TEST_VIDEO1, 0)
    rv2 = KmpMediaFileReader(TEST_VIDEO2, 0)

    sv1, = createVariant(nl, 'var1', [('v1', 'video')])
    sv2, = createVariant(nl, 'var2', [('v2', 'video')])

    st = KmpSendTimestamps()

    kmpSendStreams([
        (rv1, sv1),
        (rv2, sv2),
    ], st, 10)

    # must create at least 64 segments to run the media info free segments code
    for i in range(5):
        kmpSendStreams([
            (rv1, sv1),
        ], st, 60, realtime=False)

        rv1 = KmpMediaFileReader(TEST_VIDEO1, 0)

    kmpSendEndOfStream([sv1, sv2])

    time.sleep(2)

    # restarting nginx to remove the pending media info node

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    nl.setChannelId(channelId)

    rv3 = KmpMediaFileReader(TEST_VIDEO1, 0)

    sv3, = createVariant(nl, 'var3', [('v3', 'video')])

    st = KmpSendTimestamps()

    st.dts += 90000 * 310
    st.created += 90000 * 310

    kmpSendStreams([
        (rv3, sv3),
    ], st, 20, realtime=False)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
