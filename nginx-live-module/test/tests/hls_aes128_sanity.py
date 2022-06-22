from test_base import *

# EXPECTED:
#   20 sec audio + video

def updateConf(conf):
    server = getConfBlock(conf, ['http', 'server'])
    server.append(['pckg_enc_scheme', 'aes-128'])
    server.append(['pckg_enc_key_seed', 'keySeed$channel_id'])
    server.append(['pckg_enc_iv_seed', 'ivSeed$channel_id'])

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
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    testDefaultStreams(channelId, __file__)