from test_base import *

# EXPECTED:
#   24 sec audio + video, then starts from the beginning for 30 sec
#   8 sec segments are used before and after the restart

def updateConf(conf):
    appendConfDirective(conf, ['live'], ['persist_bucket_size', '1'])

def stream(nl, duration, eos, initialFrameId=0, initialTs=0):
    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    st = KmpSendTimestamps()
    st.dts = initialTs
    st.created = DEFAULT_CREATED + initialTs

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')], initialFrameId)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, duration, realtime=False)

    if eos:
        kmpSendEndOfStream([sv, sa])
    else:
        time.sleep(1)
        sv.close()
        sa.close()

def setup(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=8000))

    stream(nl, 30, False)

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    nl.setChannelId(channelId)

    stream(nl, 30, True, 1000000, 100 * 90000)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
