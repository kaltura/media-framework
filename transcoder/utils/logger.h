//
//  logger.h
//  live-transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#ifndef LOGGER_h
#define LOGGER_h
#include "../core.h"


#define CATEGORY_DEFAULT "DEFAULT"
#define CATEGORY_TRANSCODING_SESSION "SESSION"
#define CATEGORY_CODEC "CODEC"
#define CATEGORY_OUTPUT "OUTPUT"
#define CATEGORY_FILTER "FILTER"
#define CATEGORY_FFMPEG "FFMPEG"
#define CATEGORY_RECEIVER "RECEIVER"
#define CATEGORY_KMP "KMP"
#define CATEGORY_HTTP_SERVER "HTTPSERVER"
#define CATEGORY_THROTTLER "THROTTLER"

void logger1(const char* category,int level,const char *fmt, ...);
void loggerFlush();
void log_init(int level);
int get_log_level(const char* category);
void set_log_level(const char* loglevel);

#define LOGGER(CATEGORY,LEVEL,FMT,...) { if (get_log_level(CATEGORY)>=LEVEL) { logger1(CATEGORY,LEVEL,FMT,__VA_ARGS__); }}
#define LOGGER0(CATEGORY,LEVEL,FMT) {  if (get_log_level(CATEGORY)>=LEVEL) { logger1(CATEGORY,LEVEL,FMT); } }

#endif /* LOGGER_h */
