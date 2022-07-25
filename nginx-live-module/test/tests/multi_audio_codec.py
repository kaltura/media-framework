from test_base import *

# EXPECTED:
#   30 sec video + 2 audios, first one matching the video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv = createTrack(nl, 'v1', 'video')
    sa1 = createTrack(nl, 'a1', 'audio')
    sa2 = createTrack(nl, 'a2', 'audio')

    nl.variant.create(NginxLiveVariant(id='main', track_ids={'video': 'v1', 'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt1', role='alternate', track_ids={'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt2', role='alternate', track_ids={'audio': 'a2'}))

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_AUDIO_MP3, 0), sa2),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa1, sa2])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
