from test_base import *
from threading import Thread, Lock

THREAD_COUNT = 5

def updateConf(conf):
    block = getConfBlock(conf, ['http', 'server'])
    block.append([['location', '/store/channel/__filler/filler'], [['proxy_pass', 'http://127.0.0.1:8002']]])

def readRequestBody(s, header):
    headerEnd = header.find('\r\n\r\n') + 4
    body = header[headerEnd:]
    header = header[:headerEnd]
    contentLength = int(re.findall('Content-Length: (\d+)', header)[0])
    while len(body) < contentLength:
        body += s.recv(contentLength - len(body))
    return body

def fillerServer(s):
    global fillerData

    header = s.recv(4096)
    if header.startswith('PUT '):
        fillerData = readRequestBody(s, header)
        res = ''
    elif header.startswith('GET '):
        lock.acquire()
        lock.release()
        res = fillerData

    s.send(getHttpResponseRegular(res))

class CreateChannelThread(Thread):
    def __init__(self, index):
        Thread.__init__(self)
        self.index = index

    def run(self):
        nl = nginxLiveClient()
        channelId = 'test%s' % self.index
        nl.channel.create(NginxLiveChannel(channelId, preset='main', filler=getFiller()))

def test(channelId=CHANNEL_ID):
    global lock

    # get filler data
    TcpServer(8002, fillerServer)

    nl = setupChannelVideoAudio(FILLER_CHANNEL_ID)
    saveFiller(nl, FILLER_CHANNEL_ID)
    nl.channel.delete(FILLER_CHANNEL_ID)

    # block filler read
    lock = Lock()
    lock.acquire()

    # start channel.create threads
    threads = []
    for i in xrange(THREAD_COUNT):
        threads.append(CreateChannelThread(i))

    for cur in threads:
        cur.start()

    time.sleep(1)

    # verify all channels are blocked
    for i in xrange(THREAD_COUNT):
        ch = nl.channel.get('test%s' % i)
        assert(ch['blocked'])

    # release the read
    lock.release()

    # wait on the threads
    alive = True
    while alive:
        alive = False
        for thread in threads:
            if thread.isAlive():
                alive = True
                break
        time.sleep(1)

    # verify all unblocked + have filler
    for i in xrange(THREAD_COUNT):
        channelId = 'test%s' % i
        ch = nl.channel.get(channelId)
        assert(not ch['blocked'])
        assert(ch['filler']['channel_id'] == FILLER_CHANNEL_ID)

    cleanupStack.reset()
    time.sleep(1)

def cleanup(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.delete(FILLER_CHANNEL_ID)
    for i in xrange(THREAD_COUNT):
        channelId = 'test%s' % i
        nl.channel.delete(channelId)
