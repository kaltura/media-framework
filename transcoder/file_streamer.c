//
//  fileReader.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "file_streamer.h"
#include "KMP/KMP.h"
#include "samples_stats.h"
#include <pthread.h>

void* thread_stream_from_file(void *vargp)
{
    file_streamer_t* args=(file_streamer_t*)vargp;
    AVFormatContext *ifmt_ctx=NULL;
    int oldLevel= get_log_level(NULL);

    log_init(AV_LOG_WARNING);
    int ret = avformat_open_input(&ifmt_ctx, args->source_file_name, NULL, NULL);
    if (ret < 0) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_FATAL,"Unable to open input %s %d (%s)",args->source_file_name,ret,av_err2str(ret));
        return NULL;
        
    }
    ret = avformat_find_stream_info(ifmt_ctx, NULL);
    if (ret < 0) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_FATAL,"segmenter: Unable to find any input streams  %d (%s)",ret,av_err2str(ret));
        return NULL;
    }
    log_init(oldLevel);
    
    
    int64_t duration=0;
    json_get_int64(GetConfig(),"input.duration",-1,&duration);
    
    bool realTime;
    json_get_bool(GetConfig(),"input.realTime",false,&realTime);
    
    int activeStream=0;
    json_get_int(GetConfig(),"input.activeStream",0,&activeStream);
    
    int randomDataPercentage;
    json_get_int(GetConfig(),"input.randomDataPercentage",0,&randomDataPercentage);
    
    AVPacket packet;
    av_init_packet(&packet);
    
    KMP_session_t kmp;
    if (KMP_connect(&kmp,"kmp://localhost:9999")<0) {
        return NULL;
    }
    KMP_send_handshake(&kmp,"1_abcdefgh","1");
    uint64_t  basePts=0;//av_rescale_q( getClock64(), clockScale, standard_timebase);
    
    AVStream *in_stream=ifmt_ctx->streams[activeStream];
    
    AVRational frame_rate={15,1};
    KMP_send_header(&kmp,in_stream->codecpar,frame_rate);
    
    LOGGER("SENDER",AV_LOG_INFO,"Realtime = %s",realTime ? "true" : "false");
    srand((int)time(NULL));
    uint64_t lastDts=0;
    int64_t start_time=av_gettime_relative();
    
    
    samples_stats_t stats;
    sample_stats_init(&stats,standard_timebase);
    
    while (!args->stop ) {
        
        if ((ret = av_read_frame(ifmt_ctx, &packet)) < 0)
        {
            av_seek_frame(ifmt_ctx,activeStream,0,AVSEEK_FLAG_FRAME);
            basePts+=lastDts;
            continue;
        }
        
        if (activeStream!=packet.stream_index) {
            av_packet_unref(&packet);
            continue;
        }
        
        AVStream *in_stream=ifmt_ctx->streams[packet.stream_index];
        
        av_packet_rescale_ts(&packet,in_stream->time_base, standard_timebase);
        packet.pts+=basePts;
        packet.dts+=basePts;
        if (duration!=-1) {
            if (packet.pts>=duration) {
                break;
            }
        }
        
        
        if (randomDataPercentage>0 && ((rand() % 100) < randomDataPercentage)) {
            LOGGER0(CATEGORY_DEFAULT,AV_LOG_FATAL,"random!");
            for (int i=0;i<packet.size;i++) {
                packet.data[i]=rand();
            }
        }
        
        if (realTime) {
            
            int64_t timePassed=av_rescale_q(packet.dts-basePts,standard_timebase,AV_TIME_BASE_Q);
            //LOGGER("SENDER",AV_LOG_DEBUG,"XXXX dt=%ld dd=%ld", (av_gettime_relative() - start_time),timePassed);
            while ((av_gettime_relative() - start_time) < timePassed) {
                
                // LOGGER0("SENDER",AV_LOG_DEBUG,"XXXX Sleep 10ms");
                av_usleep(10*1000);//10ms
            }
        }
        
        lastDts=packet.dts;
        
        
        samples_stats_add(&stats,packet.pts,packet.size);
        
        /*
        int avgBitrate;
        double fps,rate;
        GetFrameStatsAvg(&stats,&avgBitrate,&fps,&rate);
        LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"Sender: total frames: %ld bitrate %.2lf Kbit/s fps=%.2lf rate=x%.2lf",
               stats.totalFrames,
               ((double)avgBitrate)/(1000.0),
               fps,
               rate)*/
        
         KMP_send_packet(&kmp,&packet);
        
        /*
         LOGGER("SENDER",AV_LOG_DEBUG,"sent packet pts=%s dts=%s  size=%d",
         ts2str(packet.pts,true),
         ts2str(packet.dts,true),
         packet.dts,packet.size);*/
        
        
        av_packet_unref(&packet);
        
    }
    KMP_send_eof(&kmp);

    KMP_close(&kmp);
    avformat_close_input(&ifmt_ctx);
    return 0;
}


int file_streamer_start(file_streamer_t*);
int file_streamer_stop(file_streamer_t*);

int file_streamer_start(file_streamer_t* streamer)
{
    streamer->stop=false;
    pthread_create(&streamer->threadId, NULL, thread_stream_from_file,streamer);
    return 0;
}

int file_streamer_stop(file_streamer_t* streamer)
{
    if (streamer->threadId!=0)
    {
        streamer->stop=true;
    }
    return 0;
}


int file_streamer_close(file_streamer_t* streamer)
{
    if (streamer->threadId!=0)
    {
        pthread_join(streamer->threadId,NULL);
        streamer->threadId=0;
    }
    return 0;
}
