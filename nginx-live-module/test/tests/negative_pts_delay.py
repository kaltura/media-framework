from test_base import *

class KmpNegativePtsDelayReader(KmpReaderBase):
    def __init__(self, reader):
        self.reader = reader
        self.shift = None

    def getPacketType(self):
        return self.reader.getPacketType()

    def getPacketData(self):
        data = self.reader.getPacketData()
        if self.getPacketType() != KMP_PACKET_FRAME:
            return data

        created, dts, flags, ptsDelay = kmpGetFrameHeader(data)

        if self.shift is None:
            self.shift = ptsDelay

        ptsDelay -= self.shift

        return kmpSetFrameHeader(data, (created, dts, flags, ptsDelay))

    def readPacket(self):
        self.reader.readPacket()
        self.mediaInfo = self.reader.mediaInfo
        self.timescale = self.reader.timescale

# EXPECTED:
#   10 sec audio + video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpNegativePtsDelayReader(KmpMediaFileReader(TEST_VIDEO1, 0))
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 20)

    rv = KmpMediaFileReader(TEST_VIDEO2, 0)
    ra = KmpMediaFileReader(TEST_VIDEO2, 1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 20)

    kmpSendEndOfStream([sv, sa])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))
    testDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_segmenter_frame_list_copy: applying dts shift 12000, prev: 0')
    logTracker.assertContains(b'ngx_live_segmenter_frame_list_remove: resetting dts shift (2), prev: 12000')
