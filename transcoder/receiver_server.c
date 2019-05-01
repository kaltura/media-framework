//
//  listener.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 17/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "receiver_server.h"
#include "utils.h"
#include "logger.h"
#include <pthread.h>
#include "config.h"
#include "KMP/KMP.h"
#include "transcode_session.h"
#include <stdatomic.h>


int init_outputs(receiver_server_t *server,receiver_server_session_t* session,json_value_t* json)
{
    const json_value_t* outputsJson;
    json_get(json,"outputTracks",&outputsJson);
    
    for (int i=0;i<json_get_array_count(outputsJson);i++)
    {
        json_value_t outputJson;
        json_get_array_index(outputsJson,i,&outputJson);
        
        bool enabled=true;
        json_get_bool(&outputJson,"enabled",true,&enabled);
        if (!enabled) {
            char trackId[MAX_TRACK_ID];
            json_get_string(&outputJson,"trackId","",trackId);
            LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"Skipping output %s since it's disabled",trackId);
            continue;
        }
        transcode_session_output_t *pOutput=&server->outputs[server->totalOutputs];
        transcode_session_output_from_json(pOutput,&outputJson);
        strcpy(pOutput->set_id,session->set_id);
        transcode_session_add_output(session->server->transcode_session,pOutput);
        server->totalOutputs++;
    }
    return 0;
}

int receiver_server_calc_diagnostics(receiver_server_t *server)
{
    char* tmpBuf=av_malloc(4096);
    JSON_SERIALIZE_INIT(tmpBuf)
    char tmpBuf2[2048];
    sample_stats_get_diagnostics(&server->listnerStats, tmpBuf2);
    JSON_SERIALIZE_OBJECT("receiver", tmpBuf2)
    transcode_session_to_json(server->transcode_session,tmpBuf2);
    JSON_SERIALIZE_OBJECT("transcoder", tmpBuf2)
    JSON_SERIALIZE_END()
    
    
    char* oldDiag=server->lastDiagnsotics;
    pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
    server->lastDiagnsotics=tmpBuf;
    pthread_mutex_unlock(&server->diagnostics_locker); // unlock once you are done
    av_free(oldDiag);
    
    LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"calcualted diagnostics %s",server->lastDiagnsotics);
    return n;
}


void* processClient(void *vargp)
{
    receiver_server_session_t* session=( receiver_server_session_t *)vargp;
    receiver_server_t *server=session->server;
    transcode_session_t *transcode_session = server->transcode_session;
    
    json_value_t* config=GetConfig();

    AVRational frameRate;
    
    AVCodecParameters* params=avcodec_parameters_alloc();
    
    sample_stats_init(&server->listnerStats,standard_timebase);
    
    AVPacket packet;
    packet_header_t header;
    
    uint64_t lastStatsUpdated=0;
    while (true) {
        
        KMP_read_header(&session->kmpClient,&header);
        if (header.packet_type==PACKET_TYPE_EOS) {
            LOGGER(CATEGORY_KMP,AV_LOG_INFO,"[%s] recieved termination packet",session->stream_name);
            break;
        }
        if (header.packet_type==PACKET_TYPE_CONNECT) {
            
            if ( KMP_read_handshake(&session->kmpClient,&header,session->set_id,session->track_id)<0) {
                LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] Invalid mediainfo",session->stream_name);
                
            }
            sprintf(session->stream_name,"%s_%s",session->set_id,session->track_id);
            LOGGER(CATEGORY_KMP,AV_LOG_INFO,"[%s] recieved handshake",session->stream_name);
        }
        if (header.packet_type==PACKET_TYPE_MEDIA_INFO)
        {
            if (KMP_read_mediaInfo(&session->kmpClient,&header,params,&frameRate)<0) {
                LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] Invalid mediainfo",session->stream_name);
                exit (-1);
            }
            
            if (transcode_session!=NULL) {
                transcode_session_init(transcode_session,session->stream_name,params,frameRate);
                init_outputs(server,session,config);
            }
        }
        if (header.packet_type==PACKET_TYPE_FRAME)
        {
            if (KMP_readPacket(&session->kmpClient,&header,&packet)<=0) {
                break;
            }
            
            samples_stats_add(&server->listnerStats,packet.pts,packet.size);
            
            samples_stats_log(CATEGORY_RECEIVER,AV_LOG_DEBUG,&server->listnerStats,session->stream_name);
            LOGGER(CATEGORY_RECEIVER,AV_LOG_DEBUG,"[%s] received packet %s (%p)",session->stream_name,getPacketDesc(&packet),transcode_session);
            
            packet.pos=getClock64();
            
            if (transcode_session!=NULL)
            {
                transcode_session_send_packet(transcode_session,&packet);
            } 
            av_packet_unref(&packet);
            
            
        }
        
        uint64_t now=av_gettime();
        if (now-lastStatsUpdated>1000LL*1000LL) {//1 second interval
            receiver_server_calc_diagnostics(server);
            lastStatsUpdated=now;
        }
        
    }
    LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] Destorying receive thread",session->stream_name);
    
    if (transcode_session!=NULL)
    {
        transcode_session_close(transcode_session);
        for (int i=0;i<server->totalOutputs;i++){
            LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] Closing output %s",session->stream_name,server->outputs[i].track_id);
            transcode_session_output_close(&server->outputs[i]);
        }
    }
    
    avcodec_parameters_free(&params);
    
    KMP_close(&session->kmpClient);
    
    LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] Completed receive thread",session->stream_name);
    return NULL;
}

void* listenerThread(void *vargp)
{
    LOGGER0(CATEGORY_RECEIVER,AV_LOG_INFO,"listenerThread");
    
    receiver_server_t *server=(receiver_server_t *)vargp;
    transcode_session_t *transcodeContext = server->transcode_session;

    while (true)
    {
        receiver_server_session_t* session = (receiver_server_session_t*)av_malloc(sizeof(receiver_server_session_t));
        vector_add(&server->sessions,session);
        session->thread_id=0;
        session->server=server;
        if (transcodeContext==NULL) {
            sprintf(session->stream_name,"Receiver-%d",vector_total(&server->sessions));
        } else {
            session->stream_name[0]=0;
        }
        
        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"Waiting for accept on %s",socketAddress(&server->kmpServer.address));
        if (KMP_accept(&server->kmpServer,&session->kmpClient)<0) {
            return NULL;
        }
        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"Accepted client %s",socketAddress(&session->kmpClient.address));

        if (server->multiThreaded)
        {
            pthread_create(&session->thread_id, NULL, processClient, session);
        } else {
            processClient(session);
            break;
        }

    }
    
    return NULL;
}


int receiver_server_init(receiver_server_t *server)
{
    //event_init(&server->terminiate);
    
    pthread_mutex_init(&server->diagnostics_locker,NULL);
    server->lastDiagnsotics=NULL;
    int ret;
    if ((ret=KMP_listen(&server->kmpServer,server->port))<0) {
        return ret;
    }
    vector_init(&server->sessions);
    
    server->totalOutputs=0;
    return 0;
}

int receiver_server_async_listen(receiver_server_t *server)
{
    server->multiThreaded=true;
    int ret=0;
    if ( (ret=pthread_create(&server->thread_id, NULL, listenerThread, server))<0) {
        return ret;
    }
    return 0;
}
int receiver_server_sync_listen(receiver_server_t *server)
{
    server->multiThreaded=false;
    listenerThread(server);
    return 0;
}

void receiver_server_close(receiver_server_t *server)
{
    KMP_close(&server->kmpServer);
    if (server->thread_id!=0)
    {
        pthread_join(server->thread_id,NULL);
        
        for (int i=0;i<vector_total(&server->sessions);i++) {
            
            receiver_server_session_t* session=(receiver_server_session_t*)vector_get(&server->sessions,i);
            if (session->thread_id>0) {
                pthread_join(session->thread_id,NULL);
            }
            av_free(session);
        }
        server->thread_id=0;
    }
    
    pthread_mutex_destroy(&server->diagnostics_locker);
}

void receiver_server_get_diagnostics(receiver_server_t *server,char* diagnostics)
{
    pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
    strcpy(diagnostics,server->lastDiagnsotics);
    pthread_mutex_unlock(&server->diagnostics_locker);  // lock the critical section
}

