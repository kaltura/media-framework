//
//  LOGGER.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#include "logger.h"
#include "utils.h"

static int logLevel =AV_LOG_VERBOSE;

const char* getLevelStr(int level) {
    switch(level){
        case AV_LOG_PANIC: return "PANIC";
        case AV_LOG_FATAL: return "FATAL";
        case AV_LOG_ERROR: return "ERROR";
        case AV_LOG_WARNING: return "WARN";
        case AV_LOG_INFO: return "INFO";
        case AV_LOG_VERBOSE: return "VERBOSE";
        case AV_LOG_DEBUG: return "DEBUG";
    }
    return "";
}

int parseLoglevel(const char* loglevel)
{
    const struct { const char *name; int level; } log_levels[] = {
        { "quiet"  , AV_LOG_QUIET   },
        { "panic"  , AV_LOG_PANIC   },
        { "fatal"  , AV_LOG_FATAL   },
        { "error"  , AV_LOG_ERROR   },
        { "warning", AV_LOG_WARNING },
        { "info"   , AV_LOG_INFO    },
        { "verbose", AV_LOG_VERBOSE },
        { "debug"  , AV_LOG_DEBUG   },
        { "trace"  , AV_LOG_TRACE   },
    };

    for (int i=0;i<sizeof(log_levels)/sizeof(log_levels[0]);i++) {
        if (0==strcasecmp(loglevel, log_levels[i].name)) {
            return log_levels[i].level;
        }
    }
    return AV_LOG_DEBUG;
}

pthread_mutex_t logger_locker;

char logger_id[256] = {0};

void logger2(const char* category,const char* subcategory,int level,const char *fmt, bool newLine, va_list args)
{
    const char* levelStr=getLevelStr(level);

    int64_t now=getClock64();
    time_t epoch=now/1000000;
    struct tm *gm = localtime(&epoch);


    char buf[25];
    strftime(buf, 25, "%Y-%m-%dT%H:%M:%S",gm);

    pthread_mutex_lock(&logger_locker);  // lock the critical section

    FILE* out=stdout;

    fprintf( out, "%s.%03lld %s:%s %s |%s| [%p] ",buf,( (now % 1000000)/1000 ),category,subcategory!=NULL ? subcategory : "", levelStr,logger_id,pthread_self());
    if (args!=NULL) {
        vfprintf( out, fmt, args );
    } else {
        fprintf(out,"%s",fmt);
    }
    if (newLine) {
        fprintf( out, "\n" );
    }
    fflush(out);
    pthread_mutex_unlock(&logger_locker); // unlock once you are done
}



void logger1(const char* category,int level,const char *fmt, ...)
{
    va_list args;
    va_start( args, fmt );
    logger2("TRANSCODER",category,level,fmt,true,args);
    va_end( args );
}


/*
static void log_packet(const AVFormatContext *fmt_ctx, const AVPacket *pkt, const char *tag)
{
    AVRational *time_base = &fmt_ctx->streams[pkt->stream_index]->time_base;

    LOGGER(AV_LOG_DEBUG,"%s:  stream_index:%d  pts:%s pts_time:%s dts:%s dts_time:%s duration:%s duration_time:%s flags:%d\n",
           tag,
           pkt->stream_index,
           av_ts2str(pkt->pts), av_ts2timestr(pkt->pts, time_base),
           av_ts2str(pkt->dts), av_ts2timestr(pkt->dts, time_base),
           av_ts2str(pkt->duration), av_ts2timestr(pkt->duration, time_base),
           pkt->flags);
}*/



/*
const char *av_default_item_name(void *ptr)
{
    return (*(AVClass **) ptr)->class_name;
}

AVClassCategory av_default_get_category(void *ptr)
{
    return (*(AVClass **) ptr)->category;
}*/

void ffmpeg_log_callback(void *ptr, int level, const char *fmt, va_list vargs)
{
    if (level>logLevel)
        return;

    char tmp[1024];
    int prefix=1;
    av_log_format_line(ptr,level,fmt,vargs,tmp,sizeof(tmp), &prefix);
    logger2 (CATEGORY_FFMPEG, ptr!=NULL ? av_default_item_name(ptr) : "",level,tmp,false,NULL);
}


void log_init(int level)
{
    logLevel=level;
    av_log_set_callback(ffmpeg_log_callback);
    pthread_mutexattr_t Attr;
    pthread_mutexattr_init(&Attr);
    pthread_mutexattr_settype(&Attr, PTHREAD_MUTEX_RECURSIVE);
    pthread_mutex_init(&logger_locker, &Attr);
}

void set_log_level(const char* loglevel) {
    logLevel=parseLoglevel(loglevel);
    if(!*logger_id) {
        json_get_string(GetConfig(),"logger.id","\0",logger_id,sizeof(logger_id));
    }
}

int get_log_level(const char* category)
{
    return logLevel;
}
void loggerFlush()
{
    fflush(stderr);
    fflush(stdout);
}
