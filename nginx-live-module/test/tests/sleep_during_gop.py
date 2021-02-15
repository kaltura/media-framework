from test_base import *

# EXPECTED:
#   50 sec video plays a small skip at ~25 sec

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

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

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)
