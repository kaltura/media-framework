from test_base import *

# EXPECTED:
#   40 sec audio + video + subtitle

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])
    ssEn = createSubtitleVariant(nl, 'sub1', 's1', 'English', 'en')
    ssEs = createSubtitleVariant(nl, 'sub2', 's2', 'Spanish', 'es')

    rv = KmpMediaFileReader(TEST_VIDEO2, 0)
    ra = KmpMediaFileReader(TEST_VIDEO2, 1)
    rsEn = KmpSRTReader(TEST_VIDEO2_CC_ENG)
    rsEs = KmpSRTReader(TEST_VIDEO2_CC_SPA)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
        (rsEn, ssEn),
        (rsEs, ssEs),
    ], st, 20)

    st.dts += 100 * 90000

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
        (rsEn, ssEn),
        (rsEs, ssEs),
    ], st, 20)

    kmpSendEndOfStream([sv, sa, ssEn, ssEs])

    time.sleep(.5)

    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))
    testDefaultStreams(channelId, __file__)
