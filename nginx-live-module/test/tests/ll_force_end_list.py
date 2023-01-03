from test_base import *

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_inactive_timeout', '10'])

FORCED_TIMELINE_ID = 'forced'

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.timeline.create(NginxLiveTimeline(id=FORCED_TIMELINE_ID, active=True))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    nl.timeline.update(NginxLiveTimeline(id=FORCED_TIMELINE_ID, end_list='forced'))

    url = getStreamUrl(channelId, 'hls-ll', timelineId=FORCED_TIMELINE_ID)
    testStream(url, __file__, 'hls-ll-' + FORCED_TIMELINE_ID)

    testLLDefaultStreams(channelId, __file__)
