from test_base import *

LOG_RESPONSES = False

PROGRAM_DATE_TIME = b'#EXT-X-PROGRAM-DATE-TIME:'
DISCONTINUITY = b'#EXT-X-DISCONTINUITY'

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_frame_process_delay', '0'])
    block.append(['ll_segmenter_close_segment_delay', '0'])

    # when comparing manifests, we check the last line to see that no parts/segments entered in between,
    # rendition reports can fool us to believe the manifests are the same, while they are not
    block = getConfBlock(conf, ['http', 'server', 'location ~ /hls-ll/(?P<channel_id>[^/]+)/tl/(?P<timeline_id>[^/]+)'])
    block.insert(0, ['pckg_m3u8_rendition_reports', 'off'])

def getLastLine(s):
    newLine = s.rstrip().rfind(b'\n')
    if newLine < 0:
        return s
    return s[(newLine + 1):]

def parseDateTime(dateLine):
    dateLine = dateLine.decode('utf8')
    date, millis = dateLine[len(PROGRAM_DATE_TIME):].split('.')
    date = time.mktime(time.strptime(date, '%Y-%m-%dT%H:%M:%S'))
    date += int(millis.split('+')[0]) / 1000.0
    return date

def splitManifest(body):
    pos = body.find(PROGRAM_DATE_TIME)
    header = body[:pos]
    data = body[pos:]

    dateLine, data = data.split(b'\n', 1)
    date = parseDateTime(dateLine)

    # move map/discontinuity from header to data
    headerLast = getLastLine(header)
    if headerLast.startswith(b'#EXT-X-MAP'):
        header = header[:-len(headerLast)]
        data = headerLast + data

    headerLast = getLastLine(header)
    if headerLast.startswith(DISCONTINUITY):
        header = header[:-len(headerLast)]
        data = headerLast + data

    return header, date, data

def skipSegments(body, date, skip):
    # get the strip size
    size = 0
    for curLine in body.split(b'\n'):
        if skip <= 0:
            break

        size += len(curLine) + 1

        # update the date
        if curLine.startswith(PROGRAM_DATE_TIME):
            date = parseDateTime(curLine)
            continue

        m = re.match(b'^#EXTINF:([0-9.]+)', curLine)
        if m is not None:
            date += float(m.groups()[0])
            continue

        if not curLine.startswith(b'#'):
            skip -= 1

    # strip the body
    body = body[size:]

    # if there is a date-time tag before the first segment, parse and remove it
    for curLine in body.split(b'\n'):
        if curLine.startswith(PROGRAM_DATE_TIME):
            date = parseDateTime(curLine)
            body = body.replace(curLine + b'\n', b'')
            break

        if not curLine.startswith(b'#'):
            break

    return (date, body)

def splitByPrefix(s, prefix):
    lines = s.split(b'\n')
    positive = []
    negative = []
    for line in lines:
        if line.startswith(prefix):
            positive.append(line)
        else:
            negative.append(line)
    return b'\n'.join(positive), b'\n'.join(negative)

class TestThread(Thread):
    def __init__(self, url):
        Thread.__init__(self)
        self.url = url
        self.done = False
        self.count = 0
        self.uniques = []

    def run(self):
        # must reuse connections, otherwise all ports are exhausted by time wait sockets
        session = requests.Session()

        while not self.done:
            body1 = session.get(self.url).content
            body2 = session.get(self.url + '?_HLS_skip=YES').content

            if getLastLine(body1) != getLastLine(body2):
                continue

            # remove the parts
            parts1, body1 = splitByPrefix(body1, b'#EXT-X-PART:')
            parts2, body2 = splitByPrefix(body2, b'#EXT-X-PART:')
            assertEndsWith(parts1, parts2)

            self.count += 1
            if len(self.uniques) == 0 or (body1, body2) != self.uniques[-1]:
                self.uniques.append((body1, body2))

            skip = re.findall(b'#EXT-X-SKIP:SKIPPED-SEGMENTS=(\d+)', body2)
            if len(skip) != 1:
                assertEquals(body1, body2)
                continue

            skip = int(skip[0])

            header1, date1, segments1 = splitManifest(body1)
            header2, date2, segments2 = splitManifest(body2)

            # ignore bitrate tags, since they can be different in skipped manifest
            _, segments1 = splitByPrefix(segments1, b'#EXT-X-BITRATE:')
            _, segments2 = splitByPrefix(segments2, b'#EXT-X-BITRATE:')

            expHeader2 = header1.replace(b'#EXT-X-VERSION:6', b'#EXT-X-VERSION:9') + b'#EXT-X-SKIP:SKIPPED-SEGMENTS=%d\n' % skip
            expDate2, expSegments2 = skipSegments(segments1, date1, skip)

            assertEquals(header2, expHeader2)
            assertLessThan(abs(date2 - expDate2), .001)
            assertEquals(segments2, expSegments2)

def test(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId, preset=LL_PRESET)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    t = TestThread(getStreamUrl(channelId, 'hls-ll', 'index-svar1-v.m3u8'))
    t.start()

    # first disc - no media info change, second disc - has media info change
    for video in [TEST_VIDEO2, TEST_VIDEO2, TEST_VIDEO1]:
        kmpSendStreams([
            (KmpMediaFileReader(video, 0), sv),
            (KmpMediaFileReader(video, 1), sa),
        ], st, 48, waitForVideoKey=True)

        st.dts += 90000 * 5
        st.created += 90000 * 5

    time.sleep(1)

    t.done = True

    t.join()
    print('tested %s requests, %s unique responses' % (t.count, len(t.uniques)))

    if LOG_RESPONSES:
        for t1, t2 in t.uniques:
            print('XXXX\n%s\nYYYY\n%s' % (t1, t2))
