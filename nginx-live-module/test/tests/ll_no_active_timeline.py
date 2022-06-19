from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 20)

    kmpSendEndOfStream([sv, sa])

    time.sleep(.5)

    logTracker.assertContains('ngx_live_segment_index_ready: no active timeline, freeing segment')
    logTracker.assertNotContains('ngx_live_persist_media_write_file: write started')
