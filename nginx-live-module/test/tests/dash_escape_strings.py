from test_base import *
import json

# EXPECTED:
#   30 sec video + 2 audios, first one matching the video

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv = createTrack(nl, 'v1', 'video')
    sa1 = createTrack(nl, 'a1', 'audio')
    sa2 = createTrack(nl, 'a2', 'audio')

    cc = {
        'cc1': {
            'label': 'English',
            'lang': '<>&',
            'is_default': True
        },
        'cc2': {
            'label': 'French',
            'lang': '"\'x',
        },
        'service3': {
            'label': 'Spanish',
            'lang': '<>&',
        },
        'service4': {
            'label': 'Russian',
            'lang': '"\'x',
        },
    }

    nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': json.dumps(cc)}))

    nl.variant.create(NginxLiveVariant(id='main', track_ids={'video': 'v1', 'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt1', role='alternate', label='Aud"&<>\'io1', lang='e"&<>\'', is_default=True, track_ids={'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt2', role='alternate', label='Audio2', lang='fre', track_ids={'audio': 'a2'}))

    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'Eng"&<>\'lish', 'e"&<>\'')

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ssEn),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa1, sa2])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    url = getStreamUrl(channelId, 'hls-fmp4', 'manifest.mpd')
    testStream(url, __file__, 'dash')
