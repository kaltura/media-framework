from test_base import *

NGX_LIVE_SEGMENT_LIST_NODE_ELTS = 118

# EXPECTED:
#   6:20 sec video looping every 6 sec, at the end plays for 20 sec

class KmpHideKeyFramesReader(KmpReaderBase):
    def __init__(self, reader, intervals):
        self.reader = reader
        self.lastKeyDts = None
        self.intervals = intervals
        self.intervalIndex = 0

    def getPacketType(self):
        return self.reader.getPacketType()

    def getPacketData(self):
        data = self.reader.getPacketData()
        if self.getPacketType() != KMP_PACKET_FRAME:
            return data

        created, dts, flags, ptsDelay = kmpGetFrameHeader(data)
        if flags & KMP_FRAME_FLAG_KEY:
            interval = self.intervals[self.intervalIndex]
            if self.lastKeyDts is not None and dts > self.lastKeyDts and dts < self.lastKeyDts + interval:
                flags &= ~KMP_FRAME_FLAG_KEY
            else:
                self.intervalIndex = (self.intervalIndex + 1) % len(self.intervals)
                self.lastKeyDts = dts
        return kmpSetFrameHeader(data, (created, dts, flags, ptsDelay))

    def readPacket(self):
        self.reader.readPacket()
        self.mediaInfo = self.reader.mediaInfo
        self.timescale = self.reader.timescale

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=2000))

    sv, = createVariant(nl, 'var2', [('v2', 'video')])

    # create 118 segments with alternating durations 4, 2, 4, 2, ...
    for i in range(NGX_LIVE_SEGMENT_LIST_NODE_ELTS / 2):
        rv = KmpHideKeyFramesReader(KmpMediaFileReader(TEST_VIDEO2, 0), [1.5 * 90000, 3 * 90000])

        kmpSendStreams([
            (rv, sv),
        ], st, 5.5, realtime=20, waitForVideoKey=True)

    # create additional 2 sec segments
    rv = KmpHideKeyFramesReader(KmpMediaFileReader(TEST_VIDEO2, 0), [1.5 * 90000])

    kmpSendStreams([
        (rv, sv),
    ], st, 20, realtime=20, waitForVideoKey=True)

    kmpSendEndOfStream([sv])
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    time.sleep(2)

    testLLDefaultStreams(channelId, __file__)
    logTracker.assertContains('ngx_live_segment_list_update_last: reverting new node and incrementing previous count')
    logTracker.assertNotContains('ngx_live_segment_list_update_last: incrementing previous count')
