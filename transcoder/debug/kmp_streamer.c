//
//  kmp_streamer.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 07/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "../core.h"
#include "kmp_streamer.h"
#include <netinet/in.h>
#include <netdb.h>

#define CATEGORY_KMP_FS "KMPFS"
#define CHUNK 1024 /* read 1024 bytes at a time */

void* thread_stream_from_kmp(void *vargp)
{
    kmp_streamer_t* context=(kmp_streamer_t*)vargp;
    
    char buf[CHUNK];
    FILE *file;
    size_t nread;
    
    file = fopen("test.txt", "r");

    while (!context->stop ) {
        
        nread = fread(buf, 1, sizeof buf, context->file);
        if (nread<=0) {
            
            break;
        }

        send(context->kmp.socket,buf,nread,0);
        
         av_usleep(10);//0.01ms
    }

    KMP_close(&context->kmp);
    fclose(context->file);

    return 0;
}


int kmp_streamer_start(kmp_streamer_t* context)
{
    
    context->file = fopen(context->source_file_name, "r");

    KMP_init(&context->kmp);
    context->kmp.non_blocking=false;
    KMP_connect(&context->kmp,context->kmp_url);
                
    context->stop=false;
    pthread_create(&context->threadId, NULL, thread_stream_from_kmp,context);
    return 0;
}

int kmp_streamer_stop(kmp_streamer_t* streamer)
{
    streamer->stop=true;
    return 0;
}


int kmp_streamer_close(kmp_streamer_t* streamer)
{
    if (streamer->threadId!=0)
    {
        pthread_join(streamer->threadId,NULL);
        streamer->threadId=0;
    }
    return 0;
}
