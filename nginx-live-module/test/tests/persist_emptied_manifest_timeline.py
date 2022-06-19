from test_base import *

EMPTY_TIMELINE_ID = 'empty'

# EXPECTED:
#   8 sec audio + video
#   8 sec audio + video (from the beginning)

def test(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    nl.timeline.create(NginxLiveTimeline(id=EMPTY_TIMELINE_ID, active=True, manifest_max_segments=1))

    st = KmpSendTimestamps()

    for i in xrange(2):
        if sv is None:
            initialFrameId = i * 1000000
            sv = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'v1', 'video', initialFrameId=initialFrameId)
            sa = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'a1', 'audio', initialFrameId=initialFrameId)

        rv = KmpMediaFileReader(TEST_VIDEO1, 0)
        ra = KmpMediaFileReader(TEST_VIDEO1, 1)

        kmpSendStreams([
            (rv, sv),
            (ra, sa),
        ], st, 8)

        kmpSendEndOfStream([sv, sa])
        sv = sa = None

        nl.timeline.update(NginxLiveTimeline(id=EMPTY_TIMELINE_ID, active=False, end_list=True))

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

def validate(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)

    req = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'index-svar1.m3u8', EMPTY_TIMELINE_ID))
    assert(req.status_code == 410)
    logTracker.assertContains('timeline "empty" no longer has segments')
