# livetranscoder



```
./ThirdParty/ffmpeg/ffmpeg  -hwaccel videotoolbox -loglevel info  -i ~/Sample_video/1080p60fps.mp4  -vcodec h264_videotoolbox -f null -
```




 docker run -p  2000:2000 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined  -it -v /Users/guyjacubovski/Sample_video/:/data kaltura/transcoder-dev   /build/transcoder -f /data/config.json




 todo:
 1. drop frames if cannot reach realtime
 4. send stream
 2. ack
 3. caption with GPU



docker run --cap-add=SYS_PTRACE --runtime=nvidia  -it -v /home/ec2-user/video_files/:/data  983882572364.dkr.ecr.eu-west-1.amazonaws.com/transcoder-dev

# finding leaks with valgrind

1. make sure you use dev image. alternative: attach to running container and run apt-get install valgrind.
2. modify command line to valgrind --leak-check=<full|summary> <original command line>. i.e. docker run -ti dev-transcoder:latest valgrind  --leak-check=full /build/transcoder -f jsonfile
3. run container the more time the better.
4. observe logs; once program exits valgrind will report about each leak including call stack.
