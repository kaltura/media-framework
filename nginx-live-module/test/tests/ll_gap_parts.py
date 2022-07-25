from test_base import *

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_inactive_timeout', '100s'])


# EXPECTED:
#   2 sec video only
#   2 sec audio + video
#   2 sec video only
#   2 sec audio + video
#   2 sec video only

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=10000))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    for i in range(5):
        if i == 1:
            sa.send(ra.mediaInfo)

        kmpSendStreams([
            (rv, sv),
            (ra, sa if i % 2 != 0 else KmpNullSender()),
        ], st, maxDts = (i + 1) * 180000)

    kmpSendEndOfStream([sa, sv])
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    time.sleep(2)

    testLLDefaultStreams(channelId, __file__)
