# livetranscoder



```
./ThirdParty/ffmpeg/ffmpeg  -hwaccel videotoolbox -loglevel info  -i ~/Sample_video/1080p60fps.mp4  -vcodec h264_videotoolbox -f null -
```




 docker run -p  2000:2000 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined  -it -v /Users/guyjacubovski/Sample_video/:/data kaltura/transcoder-dev   /build/transcoder -f /data/config.json 




 todo:
 1. drop frames if cannot reach realtime
 2. video/audio sync?
 3. pts/dts wrap?
 4.send stream
 



docker run --cap-add=SYS_PTRACE --runtime=nvidia  -it -v /home/ec2-user/video_files/:/data  983882572364.dkr.ecr.eu-west-1.amazonaws.com/transcoder-dev 