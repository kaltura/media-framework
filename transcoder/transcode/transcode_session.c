//
//  TranscodePipeline.cpp
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#include "transcode_session.h"
#include "utils.h"
#include "logger.h"
#include "config.h"


/* initialization */
int transcode_session_init(transcode_session_t *pContext,char* name,struct AVCodecParameters* codecParams,AVRational framerate)
{
    pContext->decoders=0;
    pContext->outputs=0;
    pContext->filters=0;
    pContext->encoders=0;
    pContext->inputCodecParams=codecParams;
    strcpy(pContext->name,name);
    
    transcode_codec_t *pDecoderContext=&pContext->decoder[0];
    transcode_codec_init_decoder(pDecoderContext,codecParams,framerate);
    sprintf(pDecoderContext->name,"Decoder for input %s",name);
    pContext->decoders++;

    return 0;
}


void get_filter_config(char *filterConfig,  transcode_codec_t *pDecoderContext, transcode_session_output_t *pOutput)
{
    if (pOutput->codec_type==AVMEDIA_TYPE_VIDEO)
    {
        int n=sprintf(filterConfig,"framestep=step=%d,",pOutput->videoParams.skipFrame);
        if (pDecoderContext->nvidiaAccelerated) {
            
            n+=sprintf(filterConfig+n,"scale_npp=w=%d:h=%d:interp_algo=%s",
                    pOutput->videoParams.width,
                    pOutput->videoParams.height,
                    "super");
                    
            //in case of use software encoder we need to copy to CPU memory
            if (strcmp(pOutput->codec,"libx264")==0) {
                n+=sprintf(filterConfig+n,",hwdownload");
            }
        } else {
            n+=sprintf(filterConfig+n,"scale=w=%d:h=%d:sws_flags=%s",
                    pOutput->videoParams.width,
                    pOutput->videoParams.height,
                    "lanczos");
        }
       
    }
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO)
    {
        sprintf(filterConfig,"aresample=async=1000");
    }
}

transcode_filter_t* GetFilter(transcode_session_t* pContext,transcode_session_output_t* pOutput, transcode_codec_t *pDecoderContext)
{
    char filterConfig[2048];
    get_filter_config(filterConfig, pDecoderContext, pOutput);
    
    transcode_filter_t* pFilter=NULL;
    pOutput->filterId=-1;
    for (int selectedFilter=0; selectedFilter<pContext->filters;selectedFilter++) {
        pFilter=&pContext->filter[selectedFilter];
        if (strcmp(pFilter->config,filterConfig)==0) {
            pOutput->filterId=selectedFilter;
            LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Output %s - Resuing existing filter %s",pOutput->track_id,filterConfig);
        }
    }
    if ( pOutput->filterId==-1) {
        pFilter=&pContext->filter[pContext->filters];
        int ret=transcode_filter_init(pFilter,pDecoderContext->ctx,filterConfig);
        if (ret<0) {
            LOGGER(CATEGORY_DEFAULT,AV_LOG_ERROR,"Output %s - Cannot create filter %s",pOutput->track_id,filterConfig);
            return NULL;
        }
        
        pOutput->filterId=pContext->filters++;
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Output %s - Created new  filter %s",pOutput->track_id,filterConfig);
    }
    return pFilter;
}



int config_encoder(transcode_session_output_t *pOutput,  transcode_codec_t *pDecoderContext, transcode_filter_t *pFilter, transcode_codec_t *pEncoderContext)
{
    
    int ret=-1;
    if (pOutput->codec_type==AVMEDIA_TYPE_VIDEO)
    {
        int width=pDecoderContext->ctx->width;
        int height=pDecoderContext->ctx->height;
        AVRational sample_aspect_ratio=pDecoderContext->ctx->sample_aspect_ratio;
        AVRational time_base=pDecoderContext->ctx->time_base;
        AVRational frameRate=pDecoderContext->ctx->framerate;
        enum AVPixelFormat picFormat=pDecoderContext->ctx->pix_fmt;
        AVBufferRef *hw_frames_ctx = pDecoderContext->ctx->hw_frames_ctx;

        if (pFilter) {
            
            width=av_buffersink_get_w(pFilter->sink_ctx);
            height=av_buffersink_get_h(pFilter->sink_ctx);
            picFormat=av_buffersink_get_format(pFilter->sink_ctx);
            hw_frames_ctx=av_buffersink_get_hw_frames_ctx(pFilter->sink_ctx);
            time_base=av_buffersink_get_time_base(pFilter->sink_ctx);
            sample_aspect_ratio=av_buffersink_get_sample_aspect_ratio(pFilter->sink_ctx);
            frameRate=av_buffersink_get_frame_rate(pFilter->sink_ctx);
        }
        
        ret=transcode_codec_init_video_encoder(pEncoderContext,
                               sample_aspect_ratio,
                               picFormat,
                               time_base,
                               frameRate,
                               hw_frames_ctx,
                               pOutput,
                               width,
                               height);
        
    }
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO)
    {
        ret=transcode_codec_init_audio_encoder(pEncoderContext, pFilter,pOutput);
    }
    
    sprintf(pEncoderContext->name,"Encoder for output %s",pOutput->track_id);
    return ret;
}

int transcode_session_add_output(transcode_session_t* pContext, transcode_session_output_t * pOutput)
{
    transcode_codec_t *pDecoderContext=&pContext->decoder[0];
    pContext->output[pContext->outputs++]=pOutput;
    int ret=0;
    
    if (!pOutput->passthrough)
    {
        transcode_filter_t* pFilter=GetFilter(pContext,pOutput,pDecoderContext);
        transcode_codec_t* pEncoderContext=&pContext->encoder[pContext->encoders];
        
        ret=config_encoder(pOutput, pDecoderContext, pFilter, pEncoderContext);
        if (ret<0) {
            return ret;
        }
        
        pOutput->encoderId=pContext->encoders++;
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Output %s - Added encoder %d bitrate=%d",pOutput->track_id,pOutput->encoderId,pOutput->bitrate*1000);
        
        struct AVCodecParameters* pCodecParams=avcodec_parameters_alloc();
        avcodec_parameters_from_context(pCodecParams,pEncoderContext->ctx);
        transcode_session_output_set_format(pOutput,pCodecParams,pEncoderContext->ctx->framerate);
    } else
    {
        transcode_session_output_set_format(pOutput,pContext->inputCodecParams,pDecoderContext->ctx->framerate);
        
    }
    
    return 0;
}


/* processing */
int encodeFrame(transcode_session_t *pContext,int encoderId,int outputId,AVFrame *pFrame) {
 
    transcode_codec_t* pEncoder=&pContext->encoder[encoderId];
    transcode_session_output_t* pOutput=pContext->output[outputId];
    
    LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG, "[%s] Sending packet %s to encoderId %d",
           pOutput->track_id,
           getFrameDesc(pFrame),
           encoderId);
    
    
    int ret=0;
    
    if (pFrame) {
        //key frame aligment
        if ((pFrame->flags & AV_PKT_FLAG_KEY)!=AV_PKT_FLAG_KEY)
            pFrame->pict_type=AV_PICTURE_TYPE_NONE;
        else
            pFrame->pict_type=AV_PICTURE_TYPE_I;
    }
    
    ret=transcode_codec_send_frame(pEncoder,pFrame);
    
    while (ret >= 0) {
        AVPacket *pOutPacket = av_packet_alloc();
        
        ret = transcode_codec_receive_packet(pEncoder,pOutPacket);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            
            if (ret == AVERROR_EOF) {
                LOGGER0(CATEGORY_DEFAULT, AV_LOG_INFO,"encoding completed!")
            }
            av_packet_free(&pOutPacket);
            return 0;
        }
        else if (ret < 0)
        {
            LOGGER(CATEGORY_DEFAULT, AV_LOG_ERROR,"Error during encoding %d (%s)",ret,av_err2str(ret))
            return ret;
        }
        
        LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] encoded frame %s from encoder Id %d",
               pOutput->track_id,
               getFrameDesc(pFrame),
               encoderId);
        
        
        transcode_session_output_send_output_packet(pOutput,pOutPacket);
        
        av_packet_free(&pOutPacket);
    }
    return 0;
}

int sendFrameToFilter(transcode_session_t *pContext,int filterId, AVCodecContext* pDecoderContext, AVFrame *pFrame)
{
    
    transcode_filter_t *pFilter=(transcode_filter_t *)&pContext->filter[filterId];
    LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] sending frame to filter %d (%s) %s",
           pContext->name,
           filterId,
           pContext->filter[filterId].config,
           getFrameDesc(pFrame));
    
    int ret=transcode_filter_send_frame(pFilter,pFrame);
    if (ret<0) {
        
        LOGGER(CATEGORY_DEFAULT,AV_LOG_ERROR,"[%s] failed sending frame to filterId %d (%s): %s %d (%s)",
               pContext->name,
               filterId,
               pContext->filter[filterId].config,
               getFrameDesc(pFrame),
               ret,
               av_err2str(ret));
    }
    
    while (ret >= 0) {
        AVFrame *pOutFrame = av_frame_alloc();
        ret = transcode_filter_receive_frame(pFilter,pOutFrame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            av_frame_free(&pOutFrame);
            return 0;
        }
        else if (ret < 0)
        {
            av_frame_free(&pOutFrame);
            return ret;
        }
        
        LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] recieved from filterId %d (%s): %s",
               pContext->name,
               filterId,
               pContext->filter[filterId].config,getFrameDesc(pOutFrame))
        
        
        for (int outputId=0;outputId<pContext->outputs;outputId++) {
            transcode_session_output_t *pOutput=pContext->output[outputId];
            if (pOutput->filterId==filterId && pOutput->encoderId!=-1){
                LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] sending frame from filterId %d to encoderId %d",pOutput->track_id,filterId,pOutput->encoderId);
                encodeFrame(pContext,pOutput->encoderId,outputId,pOutFrame);
            }
        }
        av_frame_free(&pOutFrame);
    }
    return 0;
}

bool shouldDrop(AVFrame *pFrame)
{
    return false;
}

int OnDecodedFrame(transcode_session_t *pContext,AVCodecContext* pDecoderContext, AVFrame *pFrame)
{
    if (pFrame==NULL) {
        
        for (int outputId=0;outputId<pContext->outputs;outputId++) {
            transcode_session_output_t *pOutput=pContext->output[outputId];
            if (pOutput->encoderId!=-1){
                LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] flushing encoderId %d for output %s",pContext->name,pOutput->encoderId,pOutput->track_id);
                encodeFrame(pContext,pOutput->encoderId,outputId,NULL);
            }
        }
        return 0;
    }
    LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] decoded: %s",pContext->name,getFrameDesc(pFrame));
        
    if (shouldDrop(pFrame))
    {
        return 0;
    }
    for (int filterId=0;filterId<pContext->filters;filterId++) {
        
        sendFrameToFilter(pContext,filterId,pDecoderContext,pFrame);
       
    }
    
    for (int outputId=0;outputId<pContext->outputs;outputId++) {
        transcode_session_output_t *pOutput=pContext->output[outputId];
        if (pOutput->filterId==-1 && pOutput->encoderId!=-1){
            LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG,"[%s] sending frame directly from decoder to encoderId %d for output %s",pContext->name,pOutput->encoderId,pOutput->track_id);
            encodeFrame(pContext,pOutput->encoderId,outputId,pFrame);
        }
    }
    
    return 0;
}

int decodePacket(transcode_session_t *transcodingContext,const AVPacket* pkt) {
    
    int ret;
    
    
    if (pkt!=NULL) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_DEBUG, "[%s] Sending packet %s to decoder",
               transcodingContext->name,
               getPacketDesc(pkt));
    }
    transcode_codec_t* pDecoder=&transcodingContext->decoder[0];
    

    ret = transcode_codec_send_packet(pDecoder, pkt);
    if (ret < 0) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_ERROR, "[%d] Error sending a packet for decoding %d (%s)",pkt->stream_index,ret,av_err2str(ret));
        return ret;
    }
    
    while (ret >= 0) {
        AVFrame *pFrame = av_frame_alloc();
        
        ret = transcode_codec_receive_frame(pDecoder, pFrame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            av_frame_free(&pFrame);
            if (ret == AVERROR_EOF) {
                LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"[%d] EOS from decode",0)
                OnDecodedFrame(transcodingContext,pDecoder->ctx,NULL);
            }
            return 0;
        }
        else if (ret < 0)
        {
            LOGGER(CATEGORY_DEFAULT,AV_LOG_ERROR,"[%d] Error during decoding %d (%s)",pkt->stream_index,ret,av_err2str(ret));
            return ret;
        }
        OnDecodedFrame(transcodingContext,pDecoder->ctx,pFrame);
        
        av_frame_free(&pFrame);
    }
    return 0;
}

int transcode_session_send_packet(transcode_session_t *pContext ,struct AVPacket* packet)
{
    bool shouldDecode=false;
    for (int i=0;i<pContext->outputs;i++) {
        transcode_session_output_t *pOutput=pContext->output[i];
        if (pOutput->passthrough)
        {
            transcode_session_output_send_output_packet(pOutput,packet);
        }
        else
        {
            shouldDecode=true;
        }
    }
    if (shouldDecode) {
       return decodePacket(pContext,packet);
    }
    return 0;
}


/* shutting down */

int transcode_session_close(transcode_session_t *session) {
    
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO, "Flushing started");
    transcode_session_send_packet(session,NULL);

    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO, "Flushing completed");
    
    for (int i=0;i<session->decoders;i++) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Closing decoder %d",i);
        transcode_codec_close(&session->decoder[i]);
    }
    for (int i=0;i<session->filters;i++) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Closing filter %d",i);
        transcode_filter_close(&session->filter[i]);
    }
    for (int i=0;i<session->encoders;i++) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Closing encoder %d",i);
        transcode_codec_close(&session->encoder[i]);
    }
    return 0;
}

int transcode_session_to_json(transcode_session_t *ctx,char* buf)
{
    
    JSON_SERIALIZE_INIT(buf)
    
    JSON_SERIALIZE_ARRAY_START("decoders")
    for (int i=0;i<ctx->decoders;i++)
    {
        transcode_codec_t* context=&ctx->decoder[i];
        char tmp[1024];
        transcode_codec_get_diagnostics(context,tmp);
        JSON_SERIALIZE_ARRAY_ITEM(tmp)
    }
    JSON_SERIALIZE_ARRAY_END()
    JSON_SERIALIZE_ARRAY_START("outputs")
    for (int i=0;i<ctx->outputs;i++)
    {
        transcode_session_output_t* output=ctx->output[i];
        char tmp[1024];
        transcode_session_output_get_diagnostics(output,tmp);
        JSON_SERIALIZE_ARRAY_ITEM(tmp)
    }
    JSON_SERIALIZE_ARRAY_END()
    
    
    JSON_SERIALIZE_END()

    return n;
}
