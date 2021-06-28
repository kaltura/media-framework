from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, max_segments=1, manifest_max_segments=1))

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    time.sleep(5)

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    logTracker.assertContains('ngx_live_persist_core_read_handler: no segments, cancelling read')
