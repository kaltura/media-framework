import re
import subprocess
from subprocess import  Popen
import logging
import hashlib
import time
import json

logging.basicConfig(level=logging.DEBUG)

ffprobe_location = "/Users/guyjacubovski/ffprobe"
hash_frames = False

class TSParser():
    def __init__(self):
        logging.debug("ctor")
        
    def convertDataStringToByteArray(self, data, pkt_size):
        m = hashlib.md5()

        a = bytearray()
        for c in data.split('\n'):
            if len(c) == 0:
                continue
            a += bytearray.fromhex(c[10:50])

        start_pos = max(0,a.find(b'\x00\x00\x00\x01\x09', 1))
        a = a[start_pos:].strip(b'\x00')
        #frame_size = len(a)
        m.update(a)

        hash = m.hexdigest()
        return hash

    def parse(self, file_name, data):

        t0 = time.time()
        out = self.ffprobe(file_name)
        t1 = time.time()
        info = json.loads(out[0])
        t2 = time.time()
        streams = info['streams']
        for s in streams:
            s['samples'] = []
            s['total_duration'] = 0

        frames = info['packets_and_frames']

        self.extract_samples(frames, streams)

        self.extract_first_last_fps(info, streams)

        self.extract_id3_info(data, info)

        info['duration'] = float(info.get('last_pts',0)) - float(info.get('first_pts',0))

        self.extract_fps_and_kfi(info)

        if 'packets_and_frames' in info:
            del info['packets_and_frames']

        t3 = time.time()

        logging.info("Finished ffprobe on %s total time %.2f seconds (ffprobe: %.2f parse json %.2f process %.2f)",
                         file_name,
                         t3-t0,
                         t1-t0,
                         t2-t1,
                         t3-t2)
        return info

    def ffprobe(self, file_name):
        cmd = [ffprobe_location, "-loglevel", "quiet",
               "-print_format", "json", "-show_frames", "-show_packets",
               "-show_streams", "-i", file_name]
        if hash_frames:
            cmd.append("-show_data")
        logging.info("running ffprobe on %s", file_name)
        p = Popen(cmd, stdout=subprocess.PIPE)
        out = p.communicate()
        return out

    def extract_samples(self, frames, streams):
        sample_hash = {}
        for f in frames:
            try:
                codec_type = f.get("codec_type", None)
                if f.get("type", None) != "frame" and codec_type != "data":
                    # print f['pts_time'], "P", f.get('pos',None), f['size']
                    if 'data' in f:
                        sample_hash[(f['pts'], f['stream_index'])] = self.convertDataStringToByteArray(f['data'], f['size'])
                    continue

                    # print f['pkt_pts_time'], "F", f.get('pkt_pos',None), f['pkt_size']

                pts = float(f['pkt_pts_time']) if 'pkt_pts_time' in f else float(f['pts_time'])
                sample = {"pts": pts,
                          "dts": float(f['pkt_dts_time']) if f.get('pkt_dts_time') else pts,
                          "pict_type": f.get('pict_type', None)}

                if codec_type == "data":
                    sample['pos'] = int(f.get('pos', 0))
                    sample['size'] = int(f.get('size', 0))

                if hash_frames:
                    sample['hash'] = sample_hash[(f['pkt_pts'], f['stream_index'])]

                stream = streams[f['stream_index']]
                stream['samples'].append(sample)
                stream['total_duration'] += float(f.get('pkt_duration_time', 0))
            except err:
                self.logging.info("Error %s", err, exc_info=True)

    @staticmethod
    def has_video(info):
        video_stream = filter(lambda f: 'video' == f.get('codec_type', None), info['streams'])
        return len(video_stream) > 0

    @staticmethod
    def extract_first_last_fps(info, streams):
        main_track = 'video' if TSParser.has_video(info) else 'audio'
        for s in streams:
            if len(s['samples']) > 0:
                s['first_pts'] = s['samples'][0].get('pts', None)
                s['last_pts'] = s['samples'][-1].get('pts', None)
                if s['codec_type'] == main_track:
                    info['first_pts'] = s['first_pts']
                    info['last_pts'] = s['last_pts']

    @staticmethod
    def extract_fps_and_kfi(info):
        video_stream = filter(lambda f: 'video' == f.get('codec_type', None), info['streams'])
        info['fps'] = 0
        info['key_frame_interval'] = 0

        if len(video_stream) > 0:

            video_samples = video_stream[0]['samples']
            avg_duration = 0

            if len(video_samples)>0:
                avg_duration = video_stream[0]['total_duration']/len(video_samples)

            key_frames = filter(lambda f: f['pict_type'] == 'I', video_samples)
            if len(key_frames) > 1:
                info['key_frame_interval'] = (key_frames[-1]['dts'] - key_frames[0]['dts']) / (len(key_frames) - 1)
            else:
                info['key_frame_interval'] = info['duration']

            if len(video_samples) > 1:
                diff_avg = (video_samples[-1]['dts'] - video_samples[0]['dts']) / (len(video_samples) - 1)
            else:
                diff_avg = 0

            if diff_avg != 0:
                fps = abs(1.0 / diff_avg)
                info['fps'] = fps
            else:
                info['fps'] = 0

    @staticmethod
    def extract_id3_info(data, info):
        id3_streams = filter(lambda f: 'ID3 ' == f.get('codec_tag_string', None), info['streams'])
        if len(id3_streams) == 1:
            id3_stream = id3_streams[0]
            for sample in id3_stream['samples']:
                index = data.find('timestamp', sample['pos'])
                if index > -1:
                    next_index = data.find('}', index)
                    timestamp_str = data[index:next_index].decode("ascii")
                    r = re.search(timestamp_re, timestamp_str)

                    if r:
                        info['timestamp_tuple'] = {'pts': float(sample['pts']),
                                                   'timestamp': float(r.group('timestamp')),
                                                   'clock': int(time.time())}

    @staticmethod
    def get_key_frames(info):
        main_stream=info['streams'][0]
        key_frames = filter(lambda f: f['pict_type'] == 'I', main_stream["samples"])
        return map(lambda f: f['pts'],key_frames)


def compare_key_frames(d1,d2):
    k1=TSParser.get_key_frames(d1)
    k2=TSParser.get_key_frames(d2)
    print "frames in A and not in B: ",set(k1) - set(k2) , "\nframes in B and not in A:",set(k2) - set(k1)

l=TSParser()

d1=l.parse("/Users/guyjacubovski/dev/live/transcoder/output_v32.ts",None)
d2=l.parse("/Users/guyjacubovski/dev/live/transcoder/output_v33.ts",None)
compare_key_frames(d1,d2)