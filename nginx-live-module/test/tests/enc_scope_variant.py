from test_base import *

# EXPECTED:
#   20 sec audio + video

def updateConf(conf):
    server = getConfBlock(conf, ['http', 'server'])
    server.append(['pckg_enc_scope', 'variant'])
    server.append(['pckg_enc_scheme', 'aes-128'])
    server.append(['pckg_enc_key_seed', 'keySeed$channel_id$pckg_variant_id'])
    server.append(['pckg_enc_iv_seed', 'ivSeed$channel_id$pckg_variant_id'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    sv1, sa1 = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    sv2, sa2 = createVariant(nl, 'var2', [('v2', 'video'), ('a2', 'audio')])
    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'en')

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv1),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv2),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ssEn),
    ], st, 20, realtime=False)

    kmpSendEndOfStream([sv1, sa1, sv2, sa2, ssEn])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
