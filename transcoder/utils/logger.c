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

static bool logOutputJson = false;

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

char context_id[256] = {0};
char channel_id[256] = {0};

#define FWRITE_STR(x) fwrite(x,1,sizeof(x)-1,out)

/*
https://tc39.es/ecma262/multipage/structured-data.html#sec-json.stringify
*/
static size_t json_escape(FILE *out, const char *str)
{
    const char *start = str;
	while (*str)
	{
		char chr = *str;

		if (chr == '"' || chr == '\\' || chr == '/')
		{
			FWRITE_STR("\\");
			putc(chr,out);
		}
		else if (chr == '\b')
		{
		    FWRITE_STR("\\b");
		}
		else if (chr == '\f')
		{
		    FWRITE_STR("\\f");
		}
		else if (chr == '\n')
		{
		    FWRITE_STR("\\n");
		}
		else if (chr == '\r')
		{
		    FWRITE_STR("\\r");
		}
		else if (chr == '\t')
		{
		    FWRITE_STR("\\t");
		}
		else if (!isprint(chr))
		{
		    FWRITE_STR("\\u");
			for (int i = 0; i < 4; i++)
			{
				int value = (chr >> 12) & 0xf;
				if (value >= 0 && value <= 9)
					putc((char)('0' + value),out);
				else if (value >= 10 && value <= 15)
					putc((char)('A' + (value - 10)),out);
				chr <<= 4;
			}
		}
		else
		{
			putc(chr,out);
		}
        str++;
	}
	return str - start;
}

typedef struct {
  char *buf;
  size_t size;
  FILE *fp;
} mem_stream_t;

static mem_stream_t aux_mem_stream = {.buf = NULL,.size = 0,.fp = NULL};

static int open_mem_stream(mem_stream_t *stream) {
    if(!stream->fp){
        stream->fp = open_memstream(&stream->buf,&stream->size);
    }
    if(!stream->fp) {
        fprintf(stderr,"ERROR: could not open_memstream - os error code %d", errno);
        return -1;
    }
    return 0;
}

static int JSONStringifyMessage(FILE *out, const char *fmt, va_list args) {
      int ret = -1;
      FWRITE_STR("\"");
      if (args!=NULL) {
        if((ret = open_mem_stream(&aux_mem_stream))){
           goto error;
        }
        if((ret = fseek(aux_mem_stream.fp, 0, SEEK_SET))) {
            fprintf(stderr,"ERROR: could not fseek %d - os error code %d", ret, errno);
            goto error;
         }
         if( (ret = vfprintf(aux_mem_stream.fp, fmt, args )) > 0){
            fflush(aux_mem_stream.fp);
            aux_mem_stream.buf[ret] = '\0';
            ret = json_escape(out, aux_mem_stream.buf);
         } else {
            fprintf(stderr,"WARNING: vfprintf error %d. os error code %d", ret, errno);
         }
      } else {
         ret = json_escape(out, fmt);
      }
error:
      FWRITE_STR("\"");
      return ret;
}

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

    if(logOutputJson) {
        fprintf( out, "{\"time\": \"%s.%03ld\", \"channelId\": \"%s\", \"category\": \"%s:%s\", \"logLevel\": \"%s\","
            "\"contextId\": \"%s\", \"pthread\":\"%lx\", \"log\": ",buf,( (now % 1000000)/1000 ), channel_id, category,
             subcategory!=NULL ? subcategory : "", levelStr,context_id,pthread_self());
        JSONStringifyMessage(out, fmt, args);
        fprintf( out, "}\n" );
    } else {
        fprintf( out, "%s.%03ld %s:%s %s |%s| [%lx] ",buf,( (now % 1000000)/1000 ),category,subcategory!=NULL ? subcategory : "", levelStr,context_id,pthread_self());
         if (args!=NULL) {
            vfprintf( out, fmt, args );
        } else {
            fwrite(fmt, strlen(fmt), 1, out);
        }
        if (newLine) {
            fprintf( out, "\n" );
        }
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
    if(!*context_id) {
        json_get_string(GetConfig(),"logger.contextId","\0",context_id,sizeof(context_id));
    }
    if (!*channel_id) {
        json_get_string(GetConfig(),"logger.channelId","\0",channel_id,sizeof(channel_id));
    }
}

int get_log_level(const char* category)
{
    return logLevel;
}

void set_log_output_json(bool val)
{
    logOutputJson = val;
}

bool get_log_output_json()
{
    return logOutputJson;
}

void loggerFlush()
{
    fflush(stderr);
    fflush(stdout);
}
