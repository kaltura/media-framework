from test_base import *

ONLY_TIMELINE_ID = 'only'

# EXPECTED:
#   26 sec audio + video
#   26 sec audio only

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
    ], st, 25, realtime=False)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.create(NginxLiveTimeline(id=ONLY_TIMELINE_ID, active=True))

    sa = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'a1', 'audio', initialFrameId=100000)
    sa.send(ra.mediaInfo)

    kmpSendStreams([
        (ra, sa),
    ], st, 25, realtime=False)

    kmpSendEndOfStream([sa])

    nl.timeline.update(NginxLiveTimeline(id=ONLY_TIMELINE_ID, end_list=True))

    for prefix in ['hls-ts', 'hls-fmp4', 'hls-aa']:
        testStream(getStreamUrl(channelId, prefix, timelineId=ONLY_TIMELINE_ID), __file__, prefix)

