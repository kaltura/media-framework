from test_base import *
import json

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

    time.sleep(.5)

    testCases = [
        ('bla',
            'ngx_http_pckg_data_init: ngx_json_parse failed -1, expected digit got 0x62'),

        ('[{"id": "i1", "id": "i2"}]',
            'ngx_json_set_str_slot: duplicate key "id"'),

        (r'[{"id": "\u1"}]',
            'ngx_json_set_str_slot: failed to decode string "\u1"'),

        ('[{}]',
            'ngx_http_pckg_data_value_json_parse: missing id'),

        ('[{"id": ""}]',
            'ngx_http_pckg_data_value_json_parse: missing id'),

        ('[{"id": "id"}]',
            'ngx_http_pckg_data_value_json_parse: must contain either value or uri, id: "id"'),

        ('[{"id": "id", "value": "val", "uri": "uri"}]',
            'ngx_http_pckg_data_value_json_parse: must not contain both value and uri, id: "id"'),

        ('true',
            'ngx_http_pckg_data_json_parse: invalid element type 2, expected array'),

        ('[true]',
            'ngx_http_pckg_data_json_parse: invalid array element type 2, expected object'),
    ]

    for value, log in testCases:
        nl.channel.update(NginxLiveChannel(id=channelId, vars={'session_data': value}))

        logTracker.init()
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))
        logTracker.assertContains(log)

        assert(res.status_code == 200)
        assert('#EXTM3U' in res.content)
