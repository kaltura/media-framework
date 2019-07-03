

#ifndef core_h
#define core_h

#include <stdio.h>
//#pragma clang diagnostic push
//#pragma clang diagnostic ignored "-Wdocumentation"

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdocumentation"
#include <libavformat/avformat.h>
#include <libavfilter/avfilter.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/opt.h>
#include <libavutil/time.h>
#include <libavutil/pixdesc.h>
#include <libavutil/timestamp.h>
#include "libavutil/intreadwrite.h"
#include "libavformat/avc.h"
#pragma GCC diagnostic pop

//#pragma clang diagnostic pop
#include <stdint.h>
#include <stdbool.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>
#include <ctype.h>

#define _S(EXP) if ((EXP)<0) { return -1;}
#ifndef u_char
#define u_char  unsigned char
#endif

#define MAX_URL_LENGTH 1024
#define MAX_DIAGNOSTICS_STRING_LENGTH 4096
#endif
