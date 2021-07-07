from test_base import *

COPY_TIMELINE_ID = 'copy'

# EXPECTED:
#   66 sec audio1 + video1

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 50, realtime=False)

    nl.timeline.create(NginxLiveTimeline(id=COPY_TIMELINE_ID, active=True,
        source=NginxLiveTimelineSource(id=TIMELINE_ID)))

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 16, realtime=False)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=COPY_TIMELINE_ID, end_list=True))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__, timelineId=COPY_TIMELINE_ID)
