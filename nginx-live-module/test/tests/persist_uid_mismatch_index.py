from test_base import *
import socket
import zlib

KLPF_HEADER_SIZE = 32
KLPF_HEADER_SIZE_START = 8
KLPF_HEADER_SIZE_END = 12
NGX_PERSIST_HEADER_FLAG_COMPRESSED = 0x40000000

# persist_opaque is set to $hostname
CHANNEL_UID_START = 0x38 + len(socket.gethostname() + ':0.1')
CHANNEL_UID_END = CHANNEL_UID_START + 8

def updateConf(conf):
    getConfBlock(conf, ['live']).append(['persist_cancel_read_if_empty', 'off'])

def setup(channelId=CHANNEL_ID):
    st = KmpSendTimestamps()

    nl = setupChannelTimeline(channelId)

    sv, sa = createVariant(nl, 'var1', [('v1', 'video'), ('a1', 'audio')])

    kmpSendStreams([
        (KmpMediaFileReader(TEST_VIDEO1, 0), sv),
        (KmpMediaFileReader(TEST_VIDEO1, 1), sa),
    ], st, 30, realtime=False)

    kmpSendEndOfStream([sv, sa])

def test(channelId=CHANNEL_ID):
    with open('/tmp/store/channel/test/index', 'rb') as f:
        d = f.read()

    # decompress
    d = d[:KLPF_HEADER_SIZE] + zlib.decompress(d[KLPF_HEADER_SIZE:], 0)
    (header_size,) = struct.unpack('<L', d[KLPF_HEADER_SIZE_START:KLPF_HEADER_SIZE_END])
    d = d[:KLPF_HEADER_SIZE_START] + struct.pack('<L', header_size & ~NGX_PERSIST_HEADER_FLAG_COMPRESSED) + d[KLPF_HEADER_SIZE_END:]

    # replace the uid
    d = d[:CHANNEL_UID_START] + '\0' * 8 + d[CHANNEL_UID_END:]

    with open('/tmp/store/channel/test/index', 'wb') as f:
        f.write(d)

    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    nl.setChannelId(channelId)

    logTracker.assertContains('ngx_live_persist_index_read_channel: uid mismatch, actual: 0000000000000000')
    assert('var1' in nl.variant.getAll())    # make sure setup was loaded
