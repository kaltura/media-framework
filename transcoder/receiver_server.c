//
//  listener.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 17/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "receiver_server.h"
#include "KMP/KMP.h"
#include "transcode_session.h"
#include "utils/throttler.h"


int atomFileWrite (char* fileName,char* content,size_t size)
{
    FILE * fp;
    char tmpFileName[1000];
    sprintf(tmpFileName,"%s.tmp",fileName);
    /* open the file for writing*/
    fp = fopen (tmpFileName,"w");
    fwrite(content,size,1,fp);
    fclose (fp);
    rename(tmpFileName,fileName);
    return 0;
}

int processedFrameCB(receiver_server_session_t *session,bool completed)
{
    uint64_t now=av_gettime();
    if (completed || now-session->lastStatsUpdated>session->diagnosticsIntervalInSeconds) {//1 second interval
        receiver_server_t *server=session->server;


        char* tmpBuf=av_malloc(MAX_DIAGNOSTICS_STRING_LENGTH);
        JSON_SERIALIZE_INIT(tmpBuf,MAX_DIAGNOSTICS_STRING_LENGTH)
        JSON_SERIALIZE_OBJECT_BEGIN("transcoder")
         transcode_session_get_diagnostics(server->transcode_session,js);
        JSON_SERIALIZE_OBJECT_END()
        JSON_SERIALIZE_OBJECT_BEGIN("receiver")
            pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
            sample_stats_get_diagnostics(&server->receiverStats,js);
            pthread_mutex_unlock(&server->diagnostics_locker);  // lock the critical section
        JSON_SERIALIZE_OBJECT_END()
        JSON_SERIALIZE_INT64("time",(uint64_t)time(NULL));
        JSON_SERIALIZE_END()

        char* oldDiag=server->lastDiagnsotics;
        pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
        server->lastDiagnsotics=tmpBuf;
        atomFileWrite("lastState.json",tmpBuf,strlen(tmpBuf));
        pthread_mutex_unlock(&server->diagnostics_locker); // unlock once you are done
        av_free(oldDiag);

        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"calculated diagnostics %s",server->lastDiagnsotics);
        session->lastStatsUpdated=now;
    }

    return 0;
}

static
int clientLoop(receiver_server_t *server,receiver_server_session_t *session,transcode_session_t *transcode_session)
{
    kmp_packet_header_t header;
    int retVal = 0;
    uint64_t received_frame_ack_id=0;
    bool autoAckMode;
    uint64_t received_frame_id=0;
    kmp_frame_position_t current_position;
    throttler_t throttler = {0};

    json_get_bool(GetConfig(),"autoAckModeEnabled",false,&autoAckMode);

    _S(throttler_init(&server->receiverStats,&throttler));

    while (retVal >= 0 && session->kmpClient.socket) {

        if( (retVal = KMP_read_header(&session->kmpClient,&header)) < 0 )
        {
            LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] KMP_read_header",session->stream_name);
            break;
        }
        if (header.packet_type==KMP_PACKET_EOS) {
            LOGGER(CATEGORY_KMP,AV_LOG_INFO,"[%s] recieved termination packet",session->stream_name);
            return 0;
        }
        if (header.packet_type==KMP_PACKET_CONNECT) {
            kmp_frame_position_t start_pos = {0};
            if ( (retVal = KMP_read_handshake(&session->kmpClient,&header,session->channel_id,session->track_id,&start_pos))<0) {
                LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] KMP_read_handshake",session->stream_name);
                break;
            } else {
                LOGGER(CATEGORY_KMP,AV_LOG_INFO,"[%s] recieved handshake: frame_id: %lld , offset: %ld transcoded_frame_id: %lld",session->stream_name,start_pos.frame_id,start_pos.offset,start_pos.transcoded_frame_id);
                transcode_session->onProcessedFrame=(transcode_session_processedFrameCB*)processedFrameCB;
                transcode_session->onProcessedFrameContext=session;
                sprintf(session->stream_name,"%s_%s",session->channel_id,session->track_id);
                _S(transcode_session_init(transcode_session,session->channel_id,session->track_id,&start_pos));
                received_frame_id=start_pos.frame_id;
            }
        }
        if (header.packet_type==KMP_PACKET_MEDIA_INFO)
        {
            transcode_mediaInfo_t* newParams=av_malloc(sizeof(transcode_mediaInfo_t));
            newParams->codecParams=avcodec_parameters_alloc();
            if ( (retVal = KMP_read_mediaInfo(&session->kmpClient,&header,newParams))<0) {
                LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] Invalid mediainfo",session->stream_name);
                break;
            }
            LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] received packet  KMP_PACKET_MEDIA_INFO",session->stream_name);

            transcode_session_async_set_mediaInfo(transcode_session, newParams);
        }
        if (header.packet_type==KMP_PACKET_FRAME)
        {
            AVPacket* packet=av_packet_alloc();
            if ( (retVal = KMP_read_packet(&session->kmpClient,&header,packet))<0) {
                LOGGER(CATEGORY_RECEIVER,AV_LOG_FATAL,"[%s] KMP_read_packet mediainfo",session->stream_name);
                 av_packet_free(&packet);
                 break;
            }
            pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
            samples_stats_add(&server->receiverStats,packet->dts,packet->pos,packet->size);
            pthread_mutex_unlock(&server->diagnostics_locker);  // lock the critical section

            throttler_process(&throttler,transcode_session);

            if(add_packet_frame_id_and_pts(packet,received_frame_id,packet->pts)){
                LOGGER(CATEGORY_RECEIVER,AV_LOG_ERROR,"[%s] failed to set frame id %lld on packet",session->stream_name,received_frame_id);
            }
            LOGGER(CATEGORY_RECEIVER,AV_LOG_DEBUG,"[%s] received packet %s (%p) #: %lld",session->stream_name,getPacketDesc(packet),transcode_session,received_frame_id);
            _S(transcode_session_async_send_packet(transcode_session, packet));
            av_packet_free(&packet);
            received_frame_id++;
            if(!autoAckMode) {
                transcode_session_get_ack_frame_id(transcode_session,&current_position);
                if (current_position.frame_id!=0 && received_frame_ack_id!=current_position.frame_id) {
                    LOGGER(CATEGORY_RECEIVER,AV_LOG_DEBUG,"[%s] sending ack for packet # : %lld",session->stream_name,current_position.frame_id);
                    _S(KMP_send_ack(&session->kmpClient,&current_position));
                    received_frame_ack_id=current_position.frame_id;
                }
            }
        }
    }
    return retVal;
}

void* processClient(void *vargp)
{
    receiver_server_session_t* session=( receiver_server_session_t *)vargp;
    receiver_server_t *server=session->server;
    transcode_session_t *transcode_session = server->transcode_session;

    json_value_t* config=GetConfig();

    json_get_int64(config,"debug.diagnosticsIntervalInSeconds",60,&session->diagnosticsIntervalInSeconds);
    session->diagnosticsIntervalInSeconds*=1000LL*1000LL;

    session->lastStatsUpdated=0;
    int retval = clientLoop(server,session,transcode_session);
    LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] Destorying receive thread. exit code is %d",session->stream_name,retval);

    if (transcode_session!=NULL)
    {
        transcode_session_close(transcode_session,retval);
    }

    KMP_close(&session->kmpClient);

    LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"[%s] Completed receive thread",session->stream_name);
    return (void*)retval;
}

void* listenerThread(void *vargp)
{
    LOGGER0(CATEGORY_RECEIVER,AV_LOG_INFO,"listenerThread");

    receiver_server_t *server=(receiver_server_t *)vargp;
    transcode_session_t *transcodeContext = server->transcode_session;

    while (true)
    {
        receiver_server_session_t* session = (receiver_server_session_t*)av_malloc(sizeof(receiver_server_session_t));

        sample_stats_init(&server->receiverStats,standard_timebase);

        vector_add(&server->sessions,session);
        session->thread_id=0;
        session->server=server;
        if (transcodeContext==NULL) {
            sprintf(session->stream_name,"Receiver-%d",vector_total(&server->sessions));
        } else {
            session->stream_name[0]=0;
        }

        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"Waiting for accept on %s",socketAddress(&server->kmpServer.address));
        KMP_init(&session->kmpClient);
        _S(KMP_accept(&server->kmpServer,&session->kmpClient));

        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"Accepted client %s",socketAddress(&session->kmpClient.address));

        if (server->multiThreaded)
        {
            pthread_create(&session->thread_id, NULL, processClient, session);
        } else {
            return processClient(session);
        }
    }

    return NULL;
}


int receiver_server_init(receiver_server_t *server)
{
    //event_init(&server->terminiate);
    int clientSocket;
    json_get_int(GetConfig(),"kmp.fd",-1,&clientSocket);
    pthread_mutex_init(&server->diagnostics_locker,NULL);
    server->lastDiagnsotics=NULL;
    KMP_init(&server->kmpServer);
    server->kmpServer.listenPort=server->port;
    if(clientSocket > 0){
        LOGGER(CATEGORY_RECEIVER,AV_LOG_INFO,"kmp.fd  %d",clientSocket);
        return 0;
    } else {
        int ret;
        if ((ret=KMP_listen(&server->kmpServer))<0) {
            return ret;
        }
    }
    vector_init(&server->sessions);
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
    return (int)listenerThread(server);
}

void receiver_server_close(receiver_server_t *server)
{
    KMP_close(&server->kmpServer);

     for (int i=0;i<vector_total(&server->sessions);i++) {

        receiver_server_session_t* session=(receiver_server_session_t*)vector_get(&server->sessions,i);
        KMP_close(&session->kmpClient);
     }

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

void receiver_server_get_diagnostics(receiver_server_t *server,json_writer_ctx_t js)
{
    pthread_mutex_lock(&server->diagnostics_locker);  // lock the critical section
    if (server->lastDiagnsotics) {
       JSON_WRITE("%s",server->lastDiagnsotics);
    }
    pthread_mutex_unlock(&server->diagnostics_locker);  // lock the critical section
}

