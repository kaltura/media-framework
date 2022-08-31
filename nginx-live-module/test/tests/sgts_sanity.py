from test_base import *

# EXPECTED:
#   10 sec audio + video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    ss = createTrack(nl, 's1', 'subtitle')
    nl.variant.create(NginxLiveVariant(id='sub1', role='alternate', track_ids={'subtitle': 's1'}))

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ss),
    ], st, 10, realtime=True)

    kmpSendEndOfStream([sv, sa])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    for bucketId in [0, 1]:
        url = NGINX_LIVE_URL + '/sgts/%s/%s/master.m3u8' % (channelId, bucketId)
        testStream(url, __file__, 'sgts-%s' % bucketId)
