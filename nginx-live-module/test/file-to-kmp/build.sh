gcc -O0 -g -Wall file_to_kmp.c -o file_to_kmp -l:libavformat.so -l:libavcodec.so -l:libavutil.so -L/usr/local/lib -I/usr/local/src/FFmpeg
