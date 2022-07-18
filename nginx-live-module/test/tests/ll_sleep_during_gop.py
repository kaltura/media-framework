from test_base import *

# EXPECTED:
#   50 sec video plays with a small skip at ~25 sec

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    pipes = [
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ]
    kmpSendStreams(pipes, st, 25)

    # wait for inactivity flush
    time.sleep(11)

    kmpSendStreams(pipes, st, 25)

    kmpSendEndOfStream([sv, sa])
    time.sleep(5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testLLDefaultStreams(channelId, __file__)

    logTracker.assertContains(b'ngx_live_lls_inactive_handler: track inactive')
