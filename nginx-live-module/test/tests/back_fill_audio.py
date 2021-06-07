from test_base import *

# EXPECTED:
#   30 sec video1
#   30 sec video1 + audio2
#   30 sec video1 + audio1

TEST_VIDEO = TEST_VIDEO2
FILLER_VIDEO = TEST_VIDEO1

def updateConf(conf):
    getConfBlock(conf, ['stream', 'server']).append(['live_kmp_read_timeout', '1000000'])
    getConfBlock(conf, ['live']).append(['persist_cancel_read_if_empty', 'off'])

def setupFiller():
    nl = setupChannelTimeline(FILLER_CHANNEL_ID, FILLER_TIMELINE_ID)

    sv = createTrack(nl, 'fv1', 'video')
    sa = createTrack(nl, 'fa1', 'audio')

    st = KmpSendTimestamps()

    kmpSendStreams([
        (KmpMediaFileReader(FILLER_VIDEO, 0), sv),
        (KmpMediaFileReader(FILLER_VIDEO, 1), sa),
    ], st, maxDuration=20, realtime=False)

    kmpSendEndOfStream([sv, sa])

    return NginxLiveFiller(channel_id=FILLER_CHANNEL_ID, timeline_id=FILLER_TIMELINE_ID)


def test(channelId=CHANNEL_ID):
    # create main channel
    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    st = KmpSendTimestamps()

    # stream video
    sv = createTrack(nl, 'v1', 'video', VARIANT_ID)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
    ], st, 30, realtime=False)

    time.sleep(1)

    # configure filler
    filler = NginxLiveFiller(channel_id=FILLER_CHANNEL_ID, timeline_id=FILLER_TIMELINE_ID)
    nl.channel.update(NginxLiveChannel(id=channelId, filler=setupFiller()))

    # stream video
    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
    ], st, 30, realtime=False)

    time.sleep(1)

    # stream video + audio
    sa = createTrack(nl, 'a1', 'audio', VARIANT_ID)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO, 1), sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)

def cleanup(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.delete(FILLER_CHANNEL_ID)
    nl.channel.delete(channelId)
