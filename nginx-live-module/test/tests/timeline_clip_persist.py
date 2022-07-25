from test_base import *

CLIP_TIMELINE_ID = 'clip'

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ], st, 25, realtime=False, waitForVideoKey=True)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    time.sleep(1)

    nl.timeline.create(NginxLiveTimeline(id=CLIP_TIMELINE_ID,
        source=NginxLiveTimelineSource(id=TIMELINE_ID,
        start_offset=4*90000, end_offset=16*90000)))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__, timelineId=CLIP_TIMELINE_ID)
