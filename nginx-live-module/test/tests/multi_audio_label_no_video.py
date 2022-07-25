from test_base import *

# EXPECTED:
#   30 sec 2 audios

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sa1 = createTrack(nl, 'a1', 'audio')
    sa2 = createTrack(nl, 'a2', 'audio')

    nl.variant.create(NginxLiveVariant(id='alt1', role='alternate', label='Audio1', lang='eng', is_default=True, track_ids={'audio': 'a1'}))
    nl.variant.create(NginxLiveVariant(id='alt2', role='alternate', label='Audio2', lang='fre', track_ids={'audio': 'a2'}))

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa1),
        (KmpMediaFileReader(TEST_VIDEO2, 1), sa2),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sa1, sa2])

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list='on'))

    testDefaultStreams(channelId, __file__)
