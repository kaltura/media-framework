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
#include "./utils/packetQueue.h"


typedef struct
{
    transcode_session_t *transcode_session;
    KMP_session_t kmpServer;
    pthread_t thread_id;
    bool multiThreaded;
    char listenAddress[MAX_URL_LENGTH];
    uint16_t port;
    vector_t sessions;
    samples_stats_t receiverStats;
    pthread_mutex_t diagnostics_locker;
    char* lastDiagnsotics;
} receiver_server_t;

typedef struct
{
    char stream_name[KMP_MAX_CHANNEL_ID+KMP_MAX_TRACK_ID+1];
    char channel_id[KMP_MAX_CHANNEL_ID];
    char track_id[KMP_MAX_TRACK_ID];
    receiver_server_t *server;
    KMP_session_t kmpClient;
    pthread_t thread_id;
    uint64_t lastStatsUpdated;
    int64_t diagnosticsIntervalInSeconds;
} receiver_server_session_t;

int receiver_server_init( receiver_server_t *server);
int receiver_server_async_listen( receiver_server_t *server);
int receiver_server_sync_listen( receiver_server_t *server);

void receiver_server_close( receiver_server_t *server);
void receiver_server_get_diagnostics( receiver_server_t *server,json_writer_ctx_t js);

#endif /* listener_h */
