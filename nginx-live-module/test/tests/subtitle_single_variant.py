from test_base import *

# EXPECTED:
#   doesn't play on iPhone, this is not a valid use case... it's only to make sure we don't crash on it

def updateConf(conf):
    server = getConfBlock(conf, ['http', 'server'])
    server.append(['pckg_enc_scope', 'channel'])
    server.append(['pckg_enc_scheme', 'cbcs'])
    server.append(['pckg_enc_key_seed', 'keySeed$channel_id'])
    server.append(['pckg_enc_iv_seed', 'ivSeed$channel_id'])

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    nl.variant.create(NginxLiveVariant(id=VARIANT_ID))

    sv, sa, ss = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio'), ('s1', 'subtitle')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ss),
    ], st, 20)

    kmpSendEndOfStream([sv, sa, ss])

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
