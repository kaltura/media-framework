from test_base import *

EMPTY_TIMELINE_ID = 'empty'

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)
    nl.timeline.create(NginxLiveTimeline(id=EMPTY_TIMELINE_ID, max_duration=1, manifest_max_duration=1))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, VARIANT_ID, [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=EMPTY_TIMELINE_ID, end_list=True))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8', EMPTY_TIMELINE_ID))
    assert(req.status_code == 400)
    logTracker.assertContains('no segments in timeline "empty"')
