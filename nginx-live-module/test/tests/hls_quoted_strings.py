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
            'label': 'Engl"\r\nish',
            'lang': 'en"\r\ng',
            'is_default': True
        }
    }

    sd = [
        { 'id': 'i"\r\n1', 'value': 'v"\r\n1', 'lang': 'l"\r\n1' },
        { 'id': 'i"\r\n2', 'uri': 'v"\r\n2' }
    ]

    nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': json.dumps(cc), 'session_data': json.dumps(sd)}))

    nl.variant.create(NginxLiveVariant(id='main', track_ids={'video': 'v1', 'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt1', role='alternate', label='Aud"\r\nio1', lang='en"\r\ng', is_default=True, track_ids={'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt2', role='alternate', label='Audio2', lang='fre', track_ids={'audio': 'a2'}))

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa1, sa2])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
