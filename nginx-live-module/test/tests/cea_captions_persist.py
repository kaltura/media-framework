from test_base import *
import json

def setup(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    cc = {
        'cc1': {
            'label': 'English',
            'lang': 'eng',
            'is_default': True
        },
        'cc3': {
            'label': 'Swedish',
            'lang': 'swe'
        }
    }

    nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': json.dumps(cc)}))

    rv = KmpMediaFileReader(TEST_VIDEO_CEA608, 0)
    ra = KmpMediaFileReader(TEST_VIDEO_CEA608, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 20)

    kmpSendEndOfStream([sv, sa])
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    time.sleep(2)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    testDefaultStreams(channelId, __file__)
