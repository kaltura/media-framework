# Transcoder

## Build

```
docker build -t kaltura/transcoder-dev -f Dockerfile.build ./
docker build -t kaltura/transcoder-dev -f Dockerfile ./
```

## Run

```
docker run -p 16543:16543 -p 18001:18001 --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it -v `pwd`/config.json:/data/config.json kaltura/transcoder-dev:latest /build/transcoder -f /data/config.json
```

# finding leaks with valgrind

1. Make sure you use the dev image, or alternatively, attach to a running container and run `apt-get install valgrind`.
2. Modify command line to `valgrind --leak-check=<full|summary> <original command line>`. For example, `docker run -ti dev-transcoder:latest valgrind  --leak-check=full /build/transcoder -f jsonfile`
3. Run the container, the more time the better.
4. Observe the logs, once program exits valgrind will report any leaks if finds including call stack.
