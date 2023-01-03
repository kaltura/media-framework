from test_base import *

# EXPECTED:
#   30 sec video2 + audio2
#   30 sec video1 + audio2
#   30 sec video2 + audio2

TEST_VIDEO = TEST_VIDEO2
FILLER_VIDEO = TEST_VIDEO1

def updateConf(conf):
    appendConfDirective(conf, ['stream', 'server'], ['live_kmp_read_timeout', '1000000'])
    appendConfDirective(conf, ['live'], ['persist_cancel_read_if_empty', 'off'])

def test(channelId=CHANNEL_ID):
    # create filler channel
    nl = setupChannelTimeline(FILLER_CHANNEL_ID, FILLER_TIMELINE_ID)

    sv = createTrack(nl, 'fv1', 'video')
    sa = createTrack(nl, 'fa1', 'audio')

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(FILLER_VIDEO, 0), sv),
        (KmpMediaFileReader(FILLER_VIDEO, 1), sa),
    ], st, maxDuration=20, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # create main channel
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', filler=getFiller()))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=TIMELINE_ID, active=True, manifest_target_duration_segments=3))

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa1),
    ], st, 30, realtime=1)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 1), sa1),
    ], st, 30, realtime=1)

    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa2),
    ], st, 30, realtime=1)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)

def cleanup(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.delete(FILLER_CHANNEL_ID)
    nl.channel.delete(channelId)
