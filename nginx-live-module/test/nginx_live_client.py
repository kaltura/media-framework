import requests

class NginxLive:
    def __init__(self, url):
        self.url = url
        self.channel = NginxLiveChannelService(self)
        self.variant = NginxLiveVariantService(self)
        self.track = NginxLiveTrackService(self)
        self.timeline = NginxLiveTimelineService(self)

    def get(self, path):
        req = requests.get(url=self.url + path)
        req.raise_for_status()
        return req.json()

    def delete(self, path):
        req = requests.delete(url=self.url + path)
        req.raise_for_status()

    @staticmethod
    def filterParams(params):
        return {k:v for k,v in params.iteritems() if v is not None}

    def post(self, path, params):
        req = requests.post(url=self.url + path, json=self.filterParams(params))
        req.raise_for_status()
        if len(req.text) == 0:
            return None
        return req.json()

    def put(self, path, params):
        req = requests.put(url=self.url + path, json=self.filterParams(params))
        req.raise_for_status()
        if len(req.text) == 0:
            return None
        return req.json()

    def setChannelId(self, id):
        self.channelId = id
        self.channelBasePath = '/channels/%s' % id

class NginxLiveChannel:
    def __init__(self, id=None, preset=None, opaque=None, segment_duration=None, filler=None, read=None, vars=None, initial_segment_index=None, mem_limit=None):
        self.id = id
        self.preset = preset
        self.opaque = opaque
        self.segment_duration = segment_duration
        self.filler = filler.__dict__ if filler is not None else None
        self.read = read
        self.vars = vars
        self.initial_segment_index = initial_segment_index
        self.mem_limit = mem_limit

class NginxLiveFiller:
    def __init__(self, channel_id=None, timeline_id=None):
        self.channel_id = channel_id
        self.timeline_id = timeline_id

class NginxLiveChannelService:
    def __init__(self, base):
        self.base = base

    def getAll(self):
        return self.base.get(
            '/channels')

    def get(self, id):
        return self.base.get(
            '/channels/%s' % id)

    def delete(self, id):
        return self.base.delete(
            '/channels/%s' % id)

    def create(self, channel):
        return self.base.post(
            '/channels',
            channel.__dict__)

    def update(self, channel):
        return self.base.put(
            '/channels/%s' % channel.id,
            channel.__dict__)

class NginxLiveVariant:
    def __init__(self, id=None, opaque=None, label=None, lang=None, role=None, is_default=None, track_ids=None):
        self.id = id
        self.opaque =opaque
        self.label = label
        self.lang = lang
        self.role = role
        self.is_default = is_default
        self.track_ids = track_ids

class NginxLiveVariantService:
    def __init__(self, base):
        self.base = base

    def getAll(self):
        return self.base.get(
            self.base.channelBasePath + '/variants')

    def delete(self, id):
        return self.base.delete(
            self.base.channelBasePath + '/variants/%s' % id)

    def create(self, variant):
        return self.base.post(
            self.base.channelBasePath + '/variants',
            variant.__dict__)

    def addTrack(self, variantId, trackId):
        return self.base.post(
            self.base.channelBasePath + '/variants/%s/tracks' % variantId,
            {'id': trackId})

class NginxLiveTrack:
    def __init__(self, id=None, opaque=None, media_type=None, group_id=None):
        self.id = id
        self.opaque =opaque
        self.media_type = media_type
        self.group_id = group_id

class NginxLiveTrackService:
    def __init__(self, base):
        self.base = base

    def getAll(self):
        return self.base.get(
            self.base.channelBasePath + '/tracks')

    def delete(self, id):
        return self.base.delete(
            self.base.channelBasePath + '/tracks/%s' % id)

    def create(self, track):
        return self.base.post(
            self.base.channelBasePath + '/tracks',
            track.__dict__)

    def update(self, track):
        return self.base.put(
            self.base.channelBasePath + '/tracks/%s' % track.id,
            track.__dict__)

class NginxLiveTimeline:
    def __init__(self, id=None, source_id=None, active=None, period_gap=None, max_segments=None, max_duration=None, start=None, end=None, manifest_max_segments=None, manifest_max_duration=None, manifest_expiry_threshold=None, manifest_target_duration_segments=None, no_truncate=None, end_list=None):
        self.id = id
        self.source_id = source_id
        self.active = active
        self.period_gap = period_gap
        self.max_segments = max_segments
        self.max_duration = max_duration
        self.start = start
        self.end = end
        self.manifest_max_segments = manifest_max_segments
        self.manifest_max_duration = manifest_max_duration
        self.manifest_expiry_threshold = manifest_expiry_threshold
        self.manifest_target_duration_segments = manifest_target_duration_segments
        self.no_truncate = no_truncate
        self.end_list = end_list

class NginxLiveTimelineService:
    def __init__(self, base):
        self.base = base

    def getAll(self):
        return self.base.get(
            self.base.channelBasePath + '/timelines')

    def get(self, id):
        return self.base.get(
            self.base.channelBasePath + '/timelines/%s' % id)

    def delete(self, id):
        return self.base.delete(
            self.base.channelBasePath + '/timelines/%s' % id)

    def create(self, timeline):
        return self.base.post(
            self.base.channelBasePath + '/timelines',
            timeline.__dict__)

    def update(self, timeline):
        return self.base.put(
            self.base.channelBasePath + '/timelines/%s' % timeline.id,
            timeline.__dict__)
