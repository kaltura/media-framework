from test_base import *

LOG_RESPONSES = False

PROGRAM_DATE_TIME = '#EXT-X-PROGRAM-DATE-TIME:'
DISCONTINUITY = '#EXT-X-DISCONTINUITY'

def updateConf(conf):
    block = getConfBlock(conf, ['live', 'preset ll'])
    block.append(['ll_segmenter_frame_process_delay', '0'])
    block.append(['ll_segmenter_close_segment_delay', '0'])

    # when comparing manifests, we check the last line to see that no parts/segments entered in between,
    # rendition reports can fool us to believe the manifests are the same, while they are not
    block = getConfBlock(conf, ['http', 'server', 'location ~ /hls-ll/(?P<channel_id>[^/]+)/tl/(?P<timeline_id>[^/]+)'])
    block.insert(0, ['pckg_m3u8_rendition_reports', 'off'])

def getLastLine(s):
    newLine = s.rstrip().rfind('\n')
    if newLine < 0:
        return s
    return s[(newLine + 1):]

def parseDateTime(dateLine):
    date, millis = dateLine[len(PROGRAM_DATE_TIME):].split('.')
    date = time.mktime(time.strptime(date, '%Y-%m-%dT%H:%M:%S'))
    date += int(millis.split('+')[0]) / 1000.0
    return date

def splitManifest(body):
    pos = body.find(PROGRAM_DATE_TIME)
    header = body[:pos]
    data = body[pos:]

    dateLine, data = data.split('\n', 1)
    date = parseDateTime(dateLine)

    if header.endswith(DISCONTINUITY + '\n'):
        header = header[:-len(DISCONTINUITY + '\n')]
        data = DISCONTINUITY + '\n' + data

    return header, date, data

def skipSegments(body, date, skip):
    size = 0
    prefix = ''
    for curLine in body.split('\n'):
        # if there is a date-time tag right after the skipped segment, parse and remove it
        if curLine.startswith(PROGRAM_DATE_TIME):
            date = parseDateTime(curLine)
            size += len(curLine) + 1
            continue

        if skip <= 0:
            if curLine.startswith(DISCONTINUITY):
                # add the discontinuity to the body after parsing the date time
                size += len(curLine) + 1
                prefix = curLine + '\n'
                continue
            break

        size += len(curLine) + 1
        m = re.match('^#EXTINF:([0-9.]+)', curLine)
        if m is not None:
            # update the date
            date += float(m.groups()[0])
            continue

        if not curLine.startswith('#'):
            skip -= 1

    return (date, prefix + body[size:])

def splitByPrefix(s, prefix):
    lines = s.split('\n')
    positive = []
    negative = []
    for line in lines:
        if line.startswith(prefix):
            positive.append(line)
        else:
            negative.append(line)
    return '\n'.join(positive), '\n'.join(negative)

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
            parts1, body1 = splitByPrefix(body1, '#EXT-X-PART:')
            parts2, body2 = splitByPrefix(body2, '#EXT-X-PART:')
            assertEndsWith(parts1, parts2)

            self.count += 1
            if len(self.uniques) == 0 or (body1, body2) != self.uniques[-1]:
                self.uniques.append((body1, body2))

            skip = re.findall('#EXT-X-SKIP:SKIPPED-SEGMENTS=(\d+)', body2)
            if len(skip) != 1:
                assertEquals(body1, body2)
                continue

            skip = int(skip[0])

            header1, date1, segments1 = splitManifest(body1)
            header2, date2, segments2 = splitManifest(body2)

            # ignore bitrate tags, since they can be different in skipped manifest
            _, segments1 = splitByPrefix(segments1, '#EXT-X-BITRATE:')
            _, segments2 = splitByPrefix(segments2, '#EXT-X-BITRATE:')

            expHeader2 = header1.replace('#EXT-X-VERSION:6', '#EXT-X-VERSION:9') + '#EXT-X-SKIP:SKIPPED-SEGMENTS=%s\n' % skip
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
    print 'tested %s requests, %s unique responses' % (t.count, len(t.uniques))

    if LOG_RESPONSES:
        for t1, t2 in t.uniques:
            print 'XXXX\n%s\nYYYY\n%s' % (t1, t2)
