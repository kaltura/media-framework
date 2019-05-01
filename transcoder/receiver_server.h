//
//  listener.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 17/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef listener_h
#define listener_h

#include <stdio.h>
#include "transcode_session.h"
#include "kalturaMediaProtocol.h"
#include "KMP/KMP.h"
#include "vector.h"

typedef void* on_terminate_request_cb();



typedef struct
{
    transcode_session_t *transcode_session;
    KMP_session_t kmpServer;
    pthread_t thread_id;
    
    bool multiThreaded;
    
    transcode_session_output_t outputs[100];
    int totalOutputs;
    samples_stats_t listnerStats;
    int port;
    vector_t sessions;
    
    pthread_mutex_t diagnostics_locker;
    char* lastDiagnsotics;
} receiver_server_t;

typedef struct
{
    char stream_name[MAX_SET_ID+MAX_TRACK_ID+1];
    char set_id[MAX_SET_ID];
    char track_id[MAX_TRACK_ID];
    receiver_server_t *server;
    KMP_session_t kmpClient;
    pthread_t thread_id;
} receiver_server_session_t;

int receiver_server_init( receiver_server_t *server);
int receiver_server_async_listen( receiver_server_t *server);
int receiver_server_sync_listen( receiver_server_t *server);

void receiver_server_close( receiver_server_t *server);
void receiver_server_get_diagnostics( receiver_server_t *server,char* diagnostics);

#endif /* listener_h */
