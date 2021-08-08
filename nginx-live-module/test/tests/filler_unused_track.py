from test_base import *

# EXPECTED:
#   30 sec video1 + audio1
#   30 sec video1 only
#   30 sec video1 + audio1
#   30 sec video2 + audio1
#   30 sec video1 + audio1

TEST_VIDEO = TEST_VIDEO2
FILLER_VIDEO = TEST_VIDEO1

CREATE_WITH_CHANNEL = False

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])
    getConfBlock(conf, ['live']).append(['persist_cancel_read_if_empty', 'off'])

def setup(channelId=CHANNEL_ID):
    # create audio+video filler channel
    nl = setupChannelTimeline(FILLER_CHANNEL_ID, FILLER_TIMELINE_ID, preset='volatile')

    sv = createTrack(nl, 'fv1', 'video')
    sa = createTrack(nl, 'fa1', 'audio')

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(FILLER_VIDEO, 0), sv),
        (KmpMediaFileReader(FILLER_VIDEO, 1), sa),
    ], st, maxDuration=20, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # create main channel
    if CREATE_WITH_CHANNEL:
        filler = getFiller()
    else:
        filler = None

    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', filler=filler))
    nl.setChannelId(channelId)
    nl.timeline.create(NginxLiveTimeline(id=TIMELINE_ID, active=True))

    createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    if filler is None:
        nl.channel.update(NginxLiveChannel(id=channelId, filler=getFiller()))

def setupVideoOnlyFiller():
    # create video only filler channel
    nl = setupChannelTimeline(FILLER_CHANNEL_ID, FILLER_TIMELINE_ID, preset='volatile')

    sv = createTrack(nl, 'fv1', 'video')

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(FILLER_VIDEO, 0), sv),
    ], st, maxDuration=20, realtime=False)

    kmpSendEndOfStream([sv])


def test(channelId=CHANNEL_ID):
    setupVideoOnlyFiller()

    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    nl.setChannelId(channelId)

    logTracker.assertContains('ngx_live_filler_setup_free_unused_tracks: freeing track')

    sv = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'v1', 'video')
    sa = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, 'a1', 'audio')

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
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

def validate(channelId=CHANNEL_ID):
    setupVideoOnlyFiller()

    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)

def cleanup(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.delete(FILLER_CHANNEL_ID)
    nl.channel.delete(channelId)
