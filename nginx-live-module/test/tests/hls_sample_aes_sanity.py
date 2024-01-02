from test_base import *

# EXPECTED:
#   20 sec audio + video

def updateConf(conf):
    serverDirs = [
        ['pckg_enc_scheme', 'cbcs'],
        ['pckg_enc_key_seed', 'keySeed$channel_id'],
        ['pckg_enc_iv_seed', 'ivSeed$channel_id'],
    ]

    for sd in serverDirs:
        appendConfDirective(conf, ['http', 'server'], sd)

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 20, realtime=False)

    kmpSendEndOfStream([sv, sa])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
