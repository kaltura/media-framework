from test_base import *

# EXPECTED:
#   30 sec audio + video + subtitle

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'eng')
    ssEs = createSubtitleVariant(nl, 'sub2', 's2', 'Spanish', 'spa')

    # to test live DASH, add realtime=1 to kmpSendStreams & uncomment this:
    # st.created = int(time.time() * 90000)

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO2, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa),
        (KmpSRTReader(TEST_VIDEO2_CC_ENG), ssEn),
        (KmpSRTReader(TEST_VIDEO2_CC_SPA), ssEs),
    ], st, 30)

    kmpSendEndOfStream([sv, sa, ssEn, ssEs])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
