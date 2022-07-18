from test_base import *

def test(channelId=CHANNEL_ID):
    setupChannelVideoAudio(FILLER_CHANNEL_ID)

    nl = nginxLiveClient()
    nl.channel.create(NginxLiveChannel(id=channelId, preset='main'))

    # missing timeline_id param
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id=channelId, preset='main', filler=
            NginxLiveFiller(channel_id=FILLER_CHANNEL_ID))), 400)
    logTracker.assertContains(b'ngx_live_filler_set_channel: missing mandatory params (2)')

    # bad preset name
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id=channelId, preset='main', filler=
            NginxLiveFiller(channel_id='bla', preset='bad', timeline_id=FILLER_TIMELINE_ID))), 400)
    logTracker.assertContains(b'ngx_live_filler_read_file: unknown preset "bad"')

    # non-existing filler channel id
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id=channelId, preset='main', filler=
            NginxLiveFiller(channel_id='bad', preset=FILLER_PRESET, timeline_id=FILLER_TIMELINE_ID))),
            404)
    logTracker.assertContains(b'ngx_live_filler_ready_handler: notif failed 404')

    nl.channel.update(NginxLiveChannel(id=channelId, preset='main', filler=getFiller()))

    # attempt to change filler
    logTracker.init()
    nl.channel.update(NginxLiveChannel(id=channelId, preset='main', filler=
        NginxLiveFiller(channel_id='bla', preset=FILLER_PRESET, timeline_id=FILLER_TIMELINE_ID)))
    logTracker.assertContains(b'ngx_live_filler_source_set: attempt to change filler from "__filler:main" to "bla:main"')

    # filler write without timeline
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id=FILLER_CHANNEL_ID,
            filler=NginxLiveFiller(save=True))), 400)
    logTracker.assertContains(b'ngx_live_filler_set_channel: missing mandatory params (1)')

    # bad timeline in filler write
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id=FILLER_CHANNEL_ID,
            filler=NginxLiveFiller(save=True, timeline_id='bad'))), 400)
    logTracker.assertContains(b'ngx_live_filler_write_file: unknown timeline "bad" in channel "__filler"')

    # filler write on channel without segments
    nl = setupChannelTimeline('empty')
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id='empty',
            filler=NginxLiveFiller(save=True, timeline_id='main'))), 400)
    logTracker.assertContains(b'ngx_live_filler_write_file: timeline must have a single period')

    # filler write on channel without tracks
    nl = setupChannelVideoAudio('empty2')
    nl.track.delete('v1')
    nl.track.delete('a1')
    logTracker.init()
    assertHttpError(lambda:
        nl.channel.update(NginxLiveChannel(id='empty2',
            filler=NginxLiveFiller(save=True, timeline_id='main'))), 400)
    logTracker.assertContains(b'ngx_live_filler_write_channel: no segments written')

def cleanup(channelId=CHANNEL_ID):
    nl = nginxLiveClient()
    for id in [channelId, FILLER_CHANNEL_ID, 'empty', 'empty2']:
        nl.channel.delete(id)
