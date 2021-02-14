from test_base import *

def updateConf(conf):
    getConfBlock(conf, ['live']).append(['persist_cancel_read_if_empty', 'off'])

def setup(channelId=CHANNEL_ID):
    global before

    nl = setupChannelTimeline(channelId, FILLER_TIMELINE_ID)
    nl.channel.update(NginxLiveChannel(id=channelId, segment_duration=6000, vars={'var': 'val'}, opaque='x' * 150, initial_segment_index=456))
    nl.setChannelId(channelId)
    nl.variant.create(NginxLiveVariant(id='no-tracks', is_default=True, label='lab', lang='lang', role='alternate', opaque='y' * 150))
    nl.track.create(NginxLiveTrack(id='v1', media_type='video', group_id='gid', opaque='z' * 150))
    nl.track.create(NginxLiveTrack(id='a1', media_type='audio'))
    nl.variant.create(NginxLiveVariant(id='av', track_ids={'video':'v1', 'audio':'a1'}))
    nl.variant.create(NginxLiveVariant(id='v', track_ids={'video':'v1'}))
    nl.variant.create(NginxLiveVariant(id='a', track_ids={'audio':'a1'}))
    nl.timeline.create(NginxLiveTimeline(id='tl', active=False, start=50, end=2000000000, max_duration=80000, max_segments=150, no_truncate=True,
        end_list=True, manifest_expiry_threshold=100000, manifest_max_duration=50000, manifest_max_segments=100, manifest_target_duration_segments=5))
    time.sleep(2)
    before = nl.channel.get(channelId)

def compareObjects(c1, c2, ignore_keys=set([])):
    result = True
    for k, v1 in c1.iteritems():
        if not k in c2:
            print 'key %s exists only in first object' % k
            result = False
            continue

        v2 = c2[k]
        if type(v1) != type(v2):
            print 'type mismatch for key %s, %s vs %s' % (k, type(v1), type(v2))
            result = False
            continue

        if k in ignore_keys:
            continue

        if type(v1) == dict:
            if not compareObjects(v1, v2, ignore_keys):
                result = False
            continue

        if v1 != v2:
            print 'different values for key %s, type %s, %s vs %s' % (k, type(v1), v1, v2)
            result = False

    return result

def test(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))
    ignore_keys = set(['uptime', 'success', 'success_size', 'success_msec'])
    compareObjects(before, nl.channel.get(channelId), ignore_keys)
