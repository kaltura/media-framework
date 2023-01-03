from test_base import *

# EXPECTED:
#   continuous 40 sec audio + video

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_inactive_timeout', '100s'])
    appendConfDirective(conf, ['live', 'preset ll'], ['persist_bucket_size', '1'])

def stream(nl, duration, eos):
    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)
    rs = KmpSRTReader(TEST_VIDEO1_CC_ENG)

    st = KmpSendTimestamps()

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')], flags=KMP_CONNECT_FLAG_CONSISTENT)
    ss = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng', flags=KMP_CONNECT_FLAG_CONSISTENT)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
        (rs, ss),
    ], st, duration)

    if eos:
        kmpSendEndOfStream([sv, sa, ss])
    else:
        time.sleep(2)
        sv.close()
        sa.close()
        ss.close()

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=8000))

    stream(nl, 20, False)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset=LL_PRESET))
    nl.setChannelId(channelId)

    stream(nl, 30, False)
    stream(nl, 40, True)

    time.sleep(2)
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testLLDefaultStreams(channelId, __file__)
