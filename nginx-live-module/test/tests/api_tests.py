from test_base import *

def test(channelId=CHANNEL_ID):
    nl = setupChannelTimeline(channelId)

    # failed channel.update (non-existing channel)
    assertHttpError(lambda: nl.channel.update(NginxLiveChannel(id='bla')), 404)

    # failed channel.update (bad segment index)
    assertHttpError(lambda: nl.channel.update(NginxLiveChannel(id=channelId, initial_segment_index=0xffffffff)), 415)

    # failed channel.update (mem limit lower than used)
    nl.track.create(NginxLiveTrack(id='a1', media_type='audio'))    # use some mem
    assertHttpError(lambda: nl.channel.update(NginxLiveChannel(id=channelId, mem_limit=0)), 400)

    # failed channel.create (missing preset param)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id='bla')), 415)

    # failed channel.create (non existing preset)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id='bla', preset='bla')), 400)

    # failed channel.create (id too long)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id='a' * 128, preset='main')), 400)

    # failed channel.create (bad segment index)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id='bla', preset='main', initial_segment_index=0xffffffff)), 415)

    # failed channel.create-no-read (bad segment index)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id='bla', preset='main', read=False, initial_segment_index=0xffffffff)), 415)

    # sanity channel.create-update
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main', mem_limit=10000000))
    ch = nl.channel.get(channelId)
    assert(ch['mem_limit'] == 10000000)

    # failed channel.create-update (bad segment index)
    assertHttpError(lambda: nl.channel.create(NginxLiveChannel(id=channelId, preset='main', initial_segment_index=0xffffffff)), 415)

    # failed variants.get (non-existing channel)
    nl.setChannelId('bla')
    assertHttpError(lambda: nl.variant.getAll(), 404)
