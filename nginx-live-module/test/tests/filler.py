from test_base import *

# EXPECTED:
#   30 sec video1 + audio1
#   30 sec video1 + audio2
#   30 sec video1 + audio1
#   30 sec video2 + audio1
#   30 sec video1 + audio1

TEST_VIDEO = TEST_VIDEO2
FILLER_VIDEO = TEST_VIDEO1

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])

def test(channelId=CHANNEL_ID):
    nl = NginxLive(NGINX_LIVE_API_URL)


    # create filler channel
    nl.channel.create(NginxLiveChannel(id=FILLER_CHANNEL_ID, preset='main'))
    nl.setChannelId(FILLER_CHANNEL_ID)
    nl.timeline.create(NginxLiveTimeline(id=FILLER_TIMELINE_ID, active=True))

    sv = createTrack(nl, 'fv1', 'video')
    sa = createTrack(nl, 'fa1', 'audio')

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(FILLER_VIDEO, 0), sv),
        (KmpMediaFileReader(FILLER_VIDEO, 1), sa),
    ], st, maxDuration=20, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # create main channel
    nl = NginxLive(NGINX_LIVE_API_URL)
    filler = NginxLiveFiller(channel_id=FILLER_CHANNEL_ID, timeline_id=FILLER_TIMELINE_ID)
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', filler=filler))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=TIMELINE_ID, active=True))

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 1), sa),
    ], st, 30)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa),
    ], st, 30)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=False))

    testDefaultStreams(channelId, __file__)
