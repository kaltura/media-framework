from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    # send video media info on the audio socket
    sa.send(rv.getPacketData())

    # non matching timescale
    sv.send(rv.mediaInfo[:(KMP_PACKET_HEADER_SIZE + 8)] + struct.pack('<L', 1000) + rv.mediaInfo[(KMP_PACKET_HEADER_SIZE + 12):])

    time.sleep(.5)

    kmpSendEndOfStream([sv, sa])

    logTracker.assertContains(b'ngx_live_media_info_node_create: attempt to change media type')
    logTracker.assertContains(b"ngx_live_media_info_node_create: input timescale 1000 doesn't match channel timescale 90000")
