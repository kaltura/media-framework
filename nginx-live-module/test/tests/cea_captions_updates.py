from test_base import *
import json

def updateConf(conf):
    appendConfDirective(conf, ['live'], ['dynamic_var_max_size', '10k'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO_CEA608, 0)
    ra = KmpMediaFileReader(TEST_VIDEO_CEA608, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendEndOfStream([sv, sa])

    maxCC = {}
    for i in range(1, 5):
        id = 'cc%d' % i
        maxCC[id] = {
            'label': 'English',
            'lang': 'eng',
            'is_default': i == 1
        }

    for i in range(1, 64):
        id = 'service%d' % i
        maxCC[id] = {
            'label': 'English',
            'lang': 'eng',
            'is_default': False
        }

    emptyCC = {}

    for i in range(2):
        nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': json.dumps(maxCC)}))
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))

        assert('INSTREAM-ID="CC1"' in res.content)
        assert('INSTREAM-ID="CC4"' in res.content)
        assert('INSTREAM-ID="SERVICE1"' in res.content)
        assert('INSTREAM-ID="SERVICE63"' in res.content)
        assert('CLOSED-CAPTIONS="CC"' in res.content)

        nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': json.dumps(emptyCC)}))
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))

        assert('INSTREAM-ID="CC1"' not in res.content)
        assert('INSTREAM-ID="SERVICE1"' not in res.content)
        assert('CLOSED-CAPTIONS=NONE' in res.content)

        nl.channel.update(NginxLiveChannel(id=channelId, vars={}))
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))

        assert('CLOSED-CAPTIONS' not in res.content)
