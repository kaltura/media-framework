from test_base import *

# EXPECTED:
#   20 sec audio + video

class KmpHideKeyFramesReader(KmpReaderBase):
    def __init__(self, reader, interval):
        self.reader = reader
        self.lastKeyDts = None
        self.interval = interval

    def getPacketType(self):
        return self.reader.getPacketType()

    def getPacketData(self):
        data = self.reader.getPacketData()
        if self.getPacketType() != KMP_PACKET_FRAME:
            return data

        created, dts, flags, ptsDelay = kmpGetFrameHeader(data)
        if flags & KMP_FRAME_FLAG_KEY:
            if self.lastKeyDts is not None and dts > self.lastKeyDts and dts < self.lastKeyDts + self.interval:
                flags &= ~KMP_FRAME_FLAG_KEY
            else:
                self.lastKeyDts = dts
        return kmpSetFrameHeader(data, (created, dts, flags, ptsDelay))

    def readPacket(self):
        self.reader.readPacket()
        self.mediaInfo = self.reader.mediaInfo
        self.timescale = self.reader.timescale

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    rv1 = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra1 = KmpMediaFileReader(TEST_VIDEO1, 1)
    rv2 = KmpHideKeyFramesReader(KmpMediaFileReader(TEST_VIDEO1, 0), 8 * 90000)

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sv2, = createVariant(nl, 'var2', [('v2', 'video')])

    kmpSendStreams([
        (rv1, sv1),
        (ra1, sa1),
        (rv2, sv2),
    ], st, 20)

    kmpSendEndOfStream([sv1, sa1, sv2])
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    time.sleep(2)

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_process_frame: postponing part start')
