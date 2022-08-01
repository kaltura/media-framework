from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 10)

    kmpSendEndOfStream([sv, sa])

    testCases = [
        ('[{"id": "i1", "value": "v1"}, {"id": "i2", "value": "v2"}]',
            '#EXT-X-SESSION-DATA:DATA-ID="i1",VALUE="v1"\n#EXT-X-SESSION-DATA:DATA-ID="i2",VALUE="v2"'),
        ('[{"id": "i1", "value": "v1", "lang": "l1"}]',
            '#EXT-X-SESSION-DATA:DATA-ID="i1",VALUE="v1",LANGUAGE="l1"'),
        ('[{"id": "i1", "uri": "u1"}]',
            '#EXT-X-SESSION-DATA:DATA-ID="i1",URI="u1"')
    ]

    for var, exp in testCases:
        nl.channel.update(NginxLiveChannel(id=channelId, vars={'session_data': var}))
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))
        assert(exp in res.content)
