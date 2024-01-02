from test_base import *

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)
    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=6000))

    rv = KmpMediaFileReader(TEST_VIDEO1, 0)
    ra = KmpMediaFileReader(TEST_VIDEO1, 1)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 11, realtime=1)

    time.sleep(1)

    url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8')
    code, _, body = http_utils.getUrl(url)
    assert(code == 200)
    assert(b'#EXT-X-PRELOAD-HINT:TYPE=PART,URI="part-2-6-svar1-v.m4s"' in body)

    threads = []
    for msn in range(4):
        for part in range(10):
            url = getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8?_HLS_msn=%s&_HLS_part=%s' % (msn, part))
            t = HttpRequestThread(url)
            t.msn = msn
            t.part = part
            threads.append(t)

    time.sleep(5)

    kmpSendStreams([
        (rv, sv),
        (ra, sa),
    ], st, 5, realtime=1)

    for t in threads:
        code, headers, body = t.join()
        blockDuration = float(headers['block-duration'][0])

        if code == 200:
            parts = re.findall(b'^#EXT-X-PART:.*,URI="part-(\d+)-(\d+)-svar1-v.m4s"$', body, re.MULTILINE)
            lastPart = tuple(map(lambda x: int(x) - 1, parts[-1]))
        else:
            lastPart = None

        if (t.msn, t.part) <= (1, 4):
            # ready immediately
            assert(code == 200)
            assert(blockDuration == 0)
            assert(lastPart == (1, 4))
        elif t.msn > 0 + 2 or t.part > 4 + 3:
            # too far ahead, fails immediately
            assert(code == 400)
            assert(blockDuration == 0)
        elif t.msn == 1:
            # last part in msn 1 gets flushed after timeout
            assert(code == 200)
            assert(blockDuration > 0.2)
            assert(lastPart == (1, 5))
        else:
            # normal blocked requests
            assert(code == 200)
            assert(blockDuration > 5)
            expected = min((t.msn, t.part), (2, 5))
            assert(lastPart >= expected)
