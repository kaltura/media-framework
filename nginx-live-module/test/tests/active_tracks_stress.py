from test_base import *
import random

LONG_TEST = 1

TRACKS = [
    ('v1', 'video'),
    ('a1', 'audio'),
    ('v2', 'video'),
    ('a2', 'audio'),
]

def updateConf(conf):
    # avoid jumps in segment index whenever the channel becomes inactive
    preset = getConfBlock(conf, ['live', 'preset main'])
    preset.append(['persist_bucket_size','1'])

    # disable persistence - always start from scratch
    block = getConfBlock(conf, ['live'])
    for key in ['persist_setup_path', 'persist_index_path', 'persist_delta_path']:
        delConfParam(block, key)

def getMasterVariants(url):
    req = requests.get(url=url)
    req.raise_for_status()
    return set(re.findall(r'^index-s([^.]+)\.m3u8$', req.content, re.MULTILINE))

def getIndexSegments(url):
    req = requests.get(url=url)
    req.raise_for_status()
    return re.findall(r'^seg-(\d+)-s[^.]+\.ts$', req.content, re.MULTILINE)

def testCycle(channelId, readers):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    for id, mediaType in TRACKS:
        nl.track.create(NginxLiveTrack(id=id, media_type=mediaType))
        nl.variant.create(NginxLiveVariant(id=id, track_ids={mediaType: id}))

    segmentCount = random.randint(5, 20)
    seq = [random.randint(1, (1 << len(TRACKS)) - 1) for i in range(segmentCount)]
    while True:
        tl_segs = [random.randint(0, 1) for i in range(segmentCount)]
        if 1 in tl_segs:
            break

    initialFrameId = 0

    senders = []
    expectedSegs = []
    expectedAny = set([])

    for seg in range(segmentCount):
        if seg > 0 and (seq[seg - 1] != seq[seg] or tl_segs[seg - 1] != tl_segs[seg]):
            kmpSendEndOfStream(senders)
            senders = []

        active = tl_segs[seg] == 1
        nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, active=active))

        if len(senders) == 0:
            initialFrameId += 1000000

            ids = []
            senders = []
            streams = []
            for i in range(len(TRACKS)):
                id, mediaType = TRACKS[i]
                if seq[seg] & (1 << i):
                    ids.append(id)

                    sender = KmpTcpSender(NGINX_LIVE_KMP_ADDR, channelId, id, mediaType, initialFrameId=initialFrameId)
                    sender.send(readers[id].mediaInfo)
                    senders.append(sender)
                else:
                    sender = KmpNullSender()

                streams.append((readers[id], sender))

        maxDts = 4 * 90000 * (seg + 1)
        kmpSendStreams(streams, st, maxDts=maxDts, realtime=False, waitForVideoKey=True)

        print ('y' if active else 'n') + ': ' + ','.join(ids)

        if active:
            expectedSegs.append(str(seg + 1))
            expectedAny.update(ids)
            expectedLast = set(ids)

    kmpSendEndOfStream(senders)

    # deactivate the timeline
    nl.timeline.update(NginxLiveTimeline(id=TIMELINE_ID, end_list=True))

    actualLast = getMasterVariants(getStreamUrl(channelId, 'hls-ts'))
    actualAny = getMasterVariants(getStreamUrl(channelId, 'hls-aa'))

    actualSegs = getIndexSegments(getStreamUrl(channelId, 'hls-ts', 'index-s%s.m3u8' % list(actualLast)[0]))
    if actualSegs != expectedSegs:
        print 'actual seg: ' + ','.join(actualSegs)
        print 'expected seg: ' + ','.join(expectedSegs)
        print 'retrying...'
        nl.channel.delete(channelId)
        return False

    print 'any: ' + ','.join(actualAny)
    print 'last: ' + ','.join(actualLast)
    print
    assert(expectedAny == actualAny)
    assert(expectedLast == actualLast)

    nl.channel.delete(channelId)

    return True

def test(channelId=CHANNEL_ID):
    seed = int(time.time())

    readers = {}
    for id, mediaType in TRACKS:
        readers[id] = KmpMemoryReader(KmpMediaFileReader(TEST_VIDEO2, 0 if mediaType == 'video' else 1), 100)

    while True:
        print 'seed: %s' % seed
        random.seed(seed)

        for reader in readers.values():
            reader.reset()

        if testCycle(channelId, readers):
            seed += 1
