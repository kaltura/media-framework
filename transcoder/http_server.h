//
//  httpServer.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef httpServer_h
#define httpServer_h

#include <stdio.h>

typedef int (*http_request_callback)(const char* uri, char* buf,int bufSize,int* bytesWritten);

typedef struct {
    int port;
    http_request_callback request;
    pthread_t thread_id;
    AVIOContext *http;
} http_server_t;

int http_server_start(http_server_t *);
int http_server_stop(http_server_t *);
int http_server_close(http_server_t *);


#endif /* httpServer_h */
