//
//  fileReader.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef fileReader_h
#define fileReader_h

#include "core.h"
#include "logger.h"
#include "config.h"
#include "utils.h"


typedef struct
{
    pthread_t threadId;
    const char* source_file_name;
    bool stop;
} file_streamer_t;

int file_streamer_start(file_streamer_t*);
int file_streamer_stop(file_streamer_t*);
int file_streamer_close(file_streamer_t* );

#endif /* fileReader_h */
