from test_base import *
import json

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

    time.sleep(.5)

    testCases = [
        ('bla',
            'ngx_http_pckg_captions_init: ngx_json_parse failed -1, expected digit got 0x62'),

        ('{"cc1":{"label": "l1","label": "l2"}}',
            'ngx_json_set_str_slot: duplicate key "label"'),

        (r'{"cc1":{"label": "\u1","label": "l2"}}',
            'ngx_json_set_str_slot: failed to decode string "\u1"'),

        ('{"cc1":{}}',
            'ngx_http_pckg_captions_service_json_parse: missing label'),

        ('{"cc1":{"label": ""}}',
            'ngx_http_pckg_captions_service_json_parse: missing label'),

        ('true',
            'ngx_http_pckg_captions_json_parse: invalid element type 1, expected object'),

        ('{"cc12":{"label": "l"}}',
            'ngx_http_pckg_captions_json_parse: invalid key "cc12"'),

        ('{"cc1":true}',
            'ngx_http_pckg_captions_json_parse: invalid value type for key "cc1"'),
    ]

    for value, log in testCases:
        nl.channel.update(NginxLiveChannel(id=channelId, vars={'closed_captions': value}))

        logTracker.init()
        res = requests.get(url=getStreamUrl(channelId, 'hls-fmp4', 'master.m3u8'))
        logTracker.assertContains(log)

        assert(res.status_code == 200)
        assert('#EXTM3U' in res.content)
