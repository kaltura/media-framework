//
//  output.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#include "transcode_session_output.h"


int transcode_session_output_init(transcode_session_output_t* pOutput)  {
    strcpy(pOutput->channel_id,"");
    strcpy(pOutput->track_id,"");
    pOutput->bitrate=-1;
    pOutput->codec_type=AVMEDIA_TYPE_UNKNOWN;
    pOutput->passthrough=true;
    pOutput->filterId=-1;
    pOutput->encoderId=-1;
    pOutput->oc=NULL;
    pOutput->videoParams.width=pOutput->videoParams.height=-1;
    pOutput->videoParams.skipFrame=1;
    pOutput->videoParams.frameRate=-1;
    memset(&pOutput->actualVideoParams, 0, sizeof(pOutput->actualVideoParams));
    memset(&pOutput->actualAudioParams, 0, sizeof(pOutput->actualAudioParams));
    
    pOutput->lastAck=-1;
    strcpy(pOutput->videoParams.level,"");
    strcpy(pOutput->videoParams.profile,"");
    pOutput->audioParams.samplingRate=pOutput->audioParams.channels=-1;
    pOutput->sender=NULL;
    
    sample_stats_init(&pOutput->stats,standard_timebase);
    return 0;
}

int print_output(transcode_session_output_t* pOutput) {
    
    if ( pOutput->passthrough) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"[%s] output configuration: mode: passthrough",pOutput->track_id);
        return 0;
    }
    if (pOutput->codec_type==AVMEDIA_TYPE_VIDEO) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"(%s) output configuration: mode: transcode bitrate: %d Kbit/s  resolution: %dx%d  profile: %s preset: %s",
               pOutput->track_id,
               pOutput->bitrate / 1000,
               pOutput->videoParams.width,
               pOutput->videoParams.height,
               pOutput->videoParams.profile,
               pOutput->videoParams.preset
               )
    }
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"(%s) output configuration: mode: transcode bitrate: %d Kbit/s  %d channels, %d Hz",
               pOutput->track_id,
               pOutput->bitrate / 1000,
               pOutput->audioParams.channels,
               pOutput->audioParams.samplingRate
               )
    }
    
    return 0;
}

int transcode_session_output_from_json(transcode_session_output_t* pOutput,const json_value_t* json)
{
    transcode_session_output_init(pOutput);

    
    json_get_string(json,"trackId","",pOutput->track_id,sizeof(pOutput->track_id));
    json_get_int(json,"bitrate",-1,&(pOutput->bitrate));
    json_get_bool(json,"passthrough",true,&(pOutput->passthrough));
    json_get_string(json,"codec","",pOutput->codec,sizeof(pOutput->codec));
    const json_value_t* pVideoParams,*pAudioParams;
    if (JSON_OK==json_get(json,"videoParams",&pVideoParams)) {
        pOutput->codec_type=AVMEDIA_TYPE_VIDEO;
        json_get_int(pVideoParams,"height",-2,&pOutput->videoParams.height);
        json_get_int(pVideoParams,"width",-2,&pOutput->videoParams.width);
        json_get_string(pVideoParams,"profile","",pOutput->videoParams.profile,sizeof(pOutput->videoParams.profile));
        json_get_string(pVideoParams,"preset","",pOutput->videoParams.preset,sizeof(pOutput->videoParams.preset));
        json_get_int(pVideoParams,"skipFrame",1,&pOutput->videoParams.skipFrame);
        
    }
    if (JSON_OK==json_get(json,"audioParams",&pAudioParams)) {
        pOutput->codec_type=AVMEDIA_TYPE_AUDIO;
        json_get_int(pAudioParams,"channels",2,&pOutput->audioParams.channels);
        json_get_int(pAudioParams,"samplingRate",48000,&pOutput->audioParams.samplingRate);
    }

    print_output(pOutput);
    return 0;
}



int transcode_session_output_send_output_packet(transcode_session_output_t *pOutput,struct AVPacket* packet)
{
    if (packet==NULL){
        return 0;
    }
    samples_stats_add(&pOutput->stats,packet->dts,packet->pos, packet->size);
    
    LOGGER(CATEGORY_OUTPUT,AV_LOG_VERBOSE,"[%s] got data: %s", pOutput->track_id,getPacketDesc(packet))
    samples_stats_log(CATEGORY_OUTPUT,AV_LOG_VERBOSE,&pOutput->stats,pOutput->track_id);
    
    if (strcmp("v33",pOutput->track_id)==0) {
    //  LOGGER0(CATEGORY_OUTPUT,AV_LOG_VERBOSE,"")
    //  av_usleep(100*1000);
    }
    if (pOutput->oc) {
        
        AVPacket* cpPacket=av_packet_clone(packet);
        
        if (cpPacket->dts<0) {
            cpPacket->dts=0;
        }
        
        if (cpPacket->dts<pOutput->lastFileDts) {
            pOutput->fileDuration+=pOutput->lastFileDts;
        }
            
        pOutput->lastFileDts=cpPacket->dts;
        cpPacket->pts+=pOutput->fileDuration;
        cpPacket->dts+=pOutput->fileDuration;
        
        av_packet_rescale_ts(cpPacket,standard_timebase, pOutput->oc->streams[0]->time_base); 
        int ret=av_write_frame(pOutput->oc, cpPacket);
    
        if (ret<0) {
            
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"[%s] cannot save frame  %d (%s)",pOutput->track_id,ret,av_err2str(ret))
        }
        av_write_frame(pOutput->oc, NULL);
        
        av_packet_free(&cpPacket);
        
    }
    
    if (pOutput->sender!=NULL)
    {
        _S(KMP_send_packet(pOutput->sender,packet));
        uint64_t frame_id;
        
        if (KMP_read_ack(pOutput->sender, &frame_id)) {
            pOutput->lastAck=frame_id;
        }
    }
    
    return 0;
}

int transcode_session_output_connect(transcode_session_output_t *pOutput,uint64_t initial_frame_id)
{
    char senderUrl[MAX_URL_LENGTH];
    json_get_string(GetConfig(),"output.streamingUrl","",senderUrl,sizeof(senderUrl));
    if (strlen(senderUrl)>0) {
        pOutput->sender=( KMP_session_t* )malloc(sizeof( KMP_session_t ));
        KMP_init(pOutput->sender);

        pOutput->sender->input_is_annex_b = pOutput->codec_type==AVMEDIA_TYPE_VIDEO && !pOutput->passthrough;

        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"[%s] connecting to %s",pOutput->track_id,senderUrl);
        _S(KMP_connect(pOutput->sender, senderUrl));
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"[%s] sending handshake (channelId: %s trackId: %s)",pOutput->track_id,pOutput->channel_id,pOutput->track_id);
        _S(KMP_send_handshake(pOutput->sender,pOutput->channel_id,pOutput->track_id,initial_frame_id));
    }
    return 0;
}

int transcode_session_output_set_media_info(transcode_session_output_t *pOutput,transcode_mediaInfo_t* extra)
{
    if (extra->codecParams->width>0) {
        pOutput->actualVideoParams.width=extra->codecParams->width;
        pOutput->actualVideoParams.height=extra->codecParams->height;
        pOutput->codec_type=AVMEDIA_TYPE_VIDEO;
    }
    if (extra->codecParams->sample_rate>0) {
        pOutput->actualAudioParams.samplingRate=extra->codecParams->sample_rate;
        pOutput->actualAudioParams.channels=extra->codecParams->channels;
        pOutput->codec_type=AVMEDIA_TYPE_AUDIO;
    }

    LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"[%s] sending header",pOutput->track_id);
    _S(KMP_send_mediainfo(pOutput->sender,extra));

    bool saveFile;
    json_get_bool(GetConfig(),"output.saveFile",false,&saveFile);
    if (saveFile && pOutput->oc==NULL) {
        char fileNamePattern[MAX_URL_LENGTH];
        char filename[MAX_URL_LENGTH];
        json_get_string(GetConfig(),"output.outputFileNamePattern","output_%s.mp4",fileNamePattern,sizeof(fileNamePattern));
        sprintf(filename,fileNamePattern, pOutput->track_id);
        //pOutput->pOutputFile= fopen(filename,"wb+");  // r for read, b for binary

        /* allocate the output media context */
        avformat_alloc_output_context2(&pOutput->oc, NULL, NULL, filename);
        if (!pOutput->oc) {
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"(%s) cannot create filename %s",pOutput->track_id,filename)
            return -1;
        }
        
        AVStream *st = avformat_new_stream(pOutput->oc, NULL);
        st->id=0;
        
        avcodec_parameters_copy(st->codecpar,extra->codecParams);
        
        int ret = avio_open(&pOutput->oc->pb, filename, AVIO_FLAG_WRITE);
        if (ret<0) {
            
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"(%s) cannot create filename %s",pOutput->track_id,filename)
            return ret;
        }
        AVDictionary* opts = NULL;

        av_dict_set(&opts, "movflags", "frag_keyframe+empty_moov", 0);

        ret = avformat_write_header(pOutput->oc, &opts);
        if (ret<0) {
            
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"(%s) cannot create filename %s - %d (%s)",pOutput->track_id,filename,ret,av_err2str(ret))
        }
        pOutput->fileDuration=0;
        pOutput->lastFileDts=0;

        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"(%s) opened filename %s",pOutput->track_id,filename);
    }
    return 0;
}



int transcode_session_output_close(transcode_session_output_t* pOutput)
{
    samples_stats_log(CATEGORY_OUTPUT,AV_LOG_DEBUG,&pOutput->stats,pOutput->track_id);
    if (pOutput->oc!=NULL) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"(%s) closing file",pOutput->track_id);
        av_write_trailer(pOutput->oc);
    
        avio_closep(&pOutput->oc->pb);
        /* free the stream */
        avformat_free_context(pOutput->oc);
    }
    if (pOutput->sender!=NULL) {
        KMP_send_eof(pOutput->sender);
        KMP_close(pOutput->sender);

        av_free(pOutput->sender);
        pOutput->sender = NULL;
    }
    return 0;
}

void transcode_session_output_get_diagnostics(transcode_session_output_t *pOutput,uint64_t recieveDts,uint64_t startProcessDts,json_writer_ctx_t js)
{
    char codecData[100]={0};
    if (pOutput->codec_type==AVMEDIA_TYPE_VIDEO)
        sprintf(codecData,"%dx%d",pOutput->actualVideoParams.width,pOutput->actualVideoParams.height);
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO)
        sprintf(codecData,"%d",pOutput->actualAudioParams.samplingRate);
    
    JSON_SERIALIZE_SCOPE_BEGIN()
    JSON_SERIALIZE_STRING("track_id",pOutput->track_id)
    JSON_SERIALIZE_INT64("totalFrames",pOutput->stats.totalFrames)
    JSON_SERIALIZE_DOUBLE("currentFrameRate",pOutput->stats.currentFrameRate)
    JSON_SERIALIZE_STRING("codecData",codecData)
    JSON_SERIALIZE_INT64("lastAck", pOutput->lastAck)
    JSON_SERIALIZE_INT64("lastDts",pOutput->stats.lastDts)
    JSON_SERIALIZE_INT("bitrate",pOutput->bitrate > 0 ? pOutput->bitrate : -1)
    JSON_SERIALIZE_INT("currenBitrate",pOutput->stats.currentBitRate)
    JSON_SERIALIZE_END()
}
