//
//  kmp_streamer.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 07/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef kmp_streamer_h
#define kmp_streamer_h

#include <stdio.h>
#include "../KMP/KMP.h"

typedef struct
{
    KMP_session_t kmp;
    FILE *file;
    pthread_t threadId;
    char source_file_name[MAX_URL_LENGTH];
    char kmp_url[MAX_URL_LENGTH];
    bool stop;
} kmp_streamer_t;

int kmp_streamer_start(kmp_streamer_t*);
int kmp_streamer_stop(kmp_streamer_t*);
int kmp_streamer_close(kmp_streamer_t* );


#endif /* kmp_streamer_h */
