from test_base import *

# EXPECTED:
#   30 sec audio + video, then starts from the beginning for 30 sec
#   8 sec segments are used before and after the restart

def updateConf(conf):
    appendConfDirective(conf, ['live', 'preset ll'], ['persist_bucket_size', '1'])
    appendConfDirective(conf, ['live', 'preset ll'], ['ll_segmenter_close_segment_delay', '500ms'])

def stream(nl, duration, eos, initialFrameId=0, initialTs=0):
    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    st = KmpSendTimestamps()
    st.dts = initialTs
    st.created = initialTs

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')], initialFrameId)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, duration)

    if eos:
        kmpSendEndOfStream([sv, sa])
    else:
        time.sleep(1)
        sv.close()
        sa.close()

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=8000))

    stream(nl, 30, False)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset=LL_PRESET))
    nl.setChannelId(channelId)

    stream(nl, 30, True, 1000000, 100 * 90000)
    time.sleep(1)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testLLDefaultStreams(channelId, __file__)
