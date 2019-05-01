//
//  output.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#include "transcode_session_output.h"
#include <libavformat/avformat.h>
#include <libavutil/timestamp.h>
#include "utils.h"
#include "logger.h"
#include "config.h"


int transcode_session_output_init(transcode_session_output_t* pOutput)  {
    strcpy(pOutput->set_id,"");
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
               pOutput->bitrate,
               pOutput->videoParams.width,
               pOutput->videoParams.height,
               pOutput->videoParams.profile,
               pOutput->videoParams.preset
               )
    }
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO) {
        LOGGER(CATEGORY_OUTPUT,AV_LOG_INFO,"(%s) output configuration: mode: transcode bitrate: %d Kbit/s  %d channels, %d Hz",
               pOutput->track_id,
               pOutput->bitrate,
               pOutput->audioParams.channels,
               pOutput->audioParams.samplingRate
               )
    }
    
    return 0;
}

int transcode_session_output_from_json(transcode_session_output_t* pOutput,const json_value_t* json)
{
    transcode_session_output_init(pOutput);

    
    json_get_string(json,"trackId","",pOutput->track_id);
    json_get_int(json,"bitrate",-1,&(pOutput->bitrate));
    json_get_bool(json,"passthrough",true,&(pOutput->passthrough));
    json_get_string(json,"codec","",pOutput->codec);
    const json_value_t* pVideoParams,*pAudioParams;
    if (JSON_OK==json_get(json,"videoParams",&pVideoParams)) {
        pOutput->codec_type=AVMEDIA_TYPE_VIDEO;
        pOutput->videoParams.width=-2;
        json_get_int(pVideoParams,"height",-1,&pOutput->videoParams.height);
        json_get_string(pVideoParams,"profile","",pOutput->videoParams.profile);
        json_get_string(pVideoParams,"preset","",pOutput->videoParams.preset);
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
    samples_stats_add(&pOutput->stats,packet->dts,packet->size);
    
    LOGGER(CATEGORY_OUTPUT,AV_LOG_DEBUG,"[%s] got data: %s", pOutput->track_id,getPacketDesc(packet))
    samples_stats_log(CATEGORY_OUTPUT,AV_LOG_DEBUG,&pOutput->stats,pOutput->track_id);
    
    if (pOutput->oc) {
        
        AVPacket* cpPacket=av_packet_clone(packet);
        
        int ret=av_write_frame(pOutput->oc, cpPacket);
    
        if (ret<0) {
            
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"[%s] cannot save frame  %d (%s)",pOutput->track_id,ret,av_err2str(ret))
        }
        av_write_frame(pOutput->oc, NULL);
        
        av_packet_free(&cpPacket);
    }
    
    if (pOutput->sender!=NULL)
    {
        KMP_send_packet(pOutput->sender,packet);
    }
    return 0;
}

int transcode_session_output_set_format(transcode_session_output_t *pOutput,struct AVCodecParameters* codecParams,AVRational framerate)
{
    char senderUrl[256];
    json_get_string(GetConfig(),"output.streamingUrl","",senderUrl);
    if (strlen(senderUrl)>0) {
        pOutput->sender=( KMP_session_t* )malloc(sizeof( KMP_session_t* ));
        KMP_connect(pOutput->sender, senderUrl);
        KMP_send_handshake(pOutput->sender,pOutput->set_id,pOutput->track_id);
        KMP_send_header(pOutput->sender,codecParams,framerate);
    }
    
    bool saveFile;
    json_get_bool(GetConfig(),"output.saveFile",false,&saveFile);
    if (saveFile && pOutput->oc==NULL) {
        char fileNamePattern[1024];
        char filename[1024];
        json_get_string(GetConfig(),"debug.outputFileNamePattern","output_%s.mp4",fileNamePattern);
        sprintf(filename,fileNamePattern, pOutput->track_id);
        //pOutput->pOutputFile= fopen(filename,"wb+");  // r for read, b for binary
        
        if (codecParams->codec_type==AVMEDIA_TYPE_VIDEO)
        {
            const AVBitStreamFilter *bsf = av_bsf_get_by_name("h264_mp4toannexb");
            int ret = av_bsf_alloc(bsf, &pOutput->bsf);
            if (ret < 0)
                return ret;
            
            ret = avcodec_parameters_copy(pOutput->bsf->par_in, codecParams);
            if (ret < 0)
                return ret;
            
            
            ret = av_bsf_init(pOutput->bsf);
            if (ret < 0) {
                return ret;
            }
            
        }

        /* allocate the output media context */
        avformat_alloc_output_context2(&pOutput->oc, NULL, NULL, filename);
        if (!pOutput->oc) {
            LOGGER(CATEGORY_OUTPUT,AV_LOG_FATAL,"(%s) cannot create filename %s",pOutput->track_id,filename)
            return -1;
        }
        

        
        AVStream *st = avformat_new_stream(pOutput->oc, NULL);

        st->id=0;
        
        
        
        avcodec_parameters_copy(st->codecpar,codecParams);
        
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

    }
    return 0;
}



int transcode_session_output_close(transcode_session_output_t* pOutput)
{
    samples_stats_log(CATEGORY_OUTPUT,AV_LOG_DEBUG,&pOutput->stats,pOutput->track_id);
    if (pOutput->oc!=NULL) {
        av_write_trailer(pOutput->oc);
    
        avio_closep(&pOutput->oc->pb);
        /* free the stream */
        avformat_free_context(pOutput->oc);
    }
    if (pOutput->sender!=NULL) {
        KMP_send_eof(pOutput->sender);
        KMP_close(pOutput->sender);

        av_free(pOutput->sender);
    }
    return 0;
}

int transcode_session_output_get_diagnostics(transcode_session_output_t *pOutput,char* buf)
{
    JSON_SERIALIZE_INIT(buf)
    JSON_SERIALIZE_STRING("set_id",pOutput->set_id)
    JSON_SERIALIZE_STRING("track_id",pOutput->track_id)
    JSON_SERIALIZE_INT("bitrate",pOutput->bitrate)
    JSON_SERIALIZE_INT("codec_type",pOutput->codec_type)
    JSON_SERIALIZE_BOOL("passthrough",pOutput->passthrough)
    char tmp[2048];
    sample_stats_get_diagnostics(&pOutput->stats, tmp);
    JSON_SERIALIZE_OBJECT("stats",tmp)
    JSON_SERIALIZE_END()
    return n;
}
