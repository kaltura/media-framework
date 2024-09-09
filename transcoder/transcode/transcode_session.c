//
//  TranscodePipeline.cpp
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#include "transcode_session.h"
#include "../utils/ackHandlerUtils.h"


/* initialization */
int transcode_session_init(transcode_session_t *ctx,char* channelId,char* trackId,kmp_frame_position_t *pos)
{
    ctx->decoders=0;
    ctx->outputs=0;
    ctx->filters=0;
    ctx->encoders=0;
    ctx->currentMediaInfo=NULL;
    ctx->input_frame_first_id=pos->frame_id;
    ctx->transcoded_frame_first_id=pos->transcoded_frame_id ? pos->transcoded_frame_id : ctx->input_frame_first_id;
    ctx->offset = pos->offset;
    ctx->ack_handler=NULL;
    strcpy(ctx->channelId,channelId);
    strcpy(ctx->trackId,trackId);
    sprintf(ctx->name,"%s_%s",channelId,trackId);
    ctx->cc_a53 = NULL;

    transcode_dropper_init(&ctx->dropper);

    clock_estimator_init(&ctx->clock_estimator);

    ctx->packetQueue.callbackContext=ctx;
    ctx->packetQueue.onMediaInfo=(packet_queue_mediaInfoCB*)transcode_session_set_media_info;
    ctx->packetQueue.onPacket=(packet_queue_packetCB*)transcode_session_send_packet;
    json_get_int(GetConfig(),"frameDropper.queueSize",2000,&ctx->packetQueue.queueSize);
    json_get_int64(GetConfig(),"frameDropper.queueDuration",10,&ctx->queueDuration);
    AVRational seconds={1,1};
    ctx->queueDuration=av_rescale_q(ctx->queueDuration,seconds,standard_timebase);

    packet_queue_init(&ctx->packetQueue);

    json_get_bool(GetConfig(),"frameDropper.enabled",false,&ctx->dropper.enabled);
    if (!ctx->dropper.enabled) {
        ctx->packetQueue.queueSize=0;
    }
    json_get_int64(GetConfig(),"frameDropper.nonKeyFrameDropperThreshold",10,&ctx->dropper.nonKeyFrameDropperThreshold);
    json_get_int64(GetConfig(),"frameDropper.decodedFrameDropperThreshold",10,&ctx->dropper.decodedFrameDropperThreshold);
    ctx->dropper.nonKeyFrameDropperThreshold=av_rescale_q(ctx->dropper.nonKeyFrameDropperThreshold,seconds,standard_timebase);
    ctx->dropper.decodedFrameDropperThreshold=av_rescale_q(ctx->dropper.decodedFrameDropperThreshold,seconds,standard_timebase);
    _S(init_policy_provider(&ctx->policy,GetConfig()));
    sample_stats_init(&ctx->processedStats,standard_timebase);


    return 0;
}

int init_outputs_from_config(transcode_session_t *ctx)
{
    const json_value_t* outputsJson;
    json_get(GetConfig(),"outputTracks",&outputsJson);

    for (int i=0;i<json_get_array_count(outputsJson);i++)
    {
        json_value_t outputJson;
        json_get_array_index(outputsJson,i,&outputJson);

        bool enabled=true;
        json_get_bool(&outputJson,"enabled",true,&enabled);
        if (!enabled) {
            char trackId[KMP_MAX_TRACK_ID];
            json_get_string(&outputJson,"trackId","",trackId,sizeof(trackId));
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Skipping output %s since it's disabled",trackId);
            continue;
        }
        _S(transcode_session_add_output(ctx,&outputJson));
    }
    return 0;
}

int transcode_session_async_set_mediaInfo(transcode_session_t *ctx,transcode_mediaInfo_t* mediaInfo)
{
    if (ctx->packetQueue.queueSize==0) {
        return transcode_session_set_media_info(ctx,mediaInfo);
    }
    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] enqueue media info",ctx->name);
    return packet_queue_write_mediaInfo(&ctx->packetQueue, mediaInfo);
}

int transcode_session_async_send_packet(transcode_session_t *ctx, struct AVPacket* packet)
{
    if (ctx->packetQueue.queueSize==0) {
        return transcode_session_send_packet(ctx,packet);
    }
    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] enqueue packet %s",ctx->name,getPacketDesc(packet));

    ctx->lastQueuedDts=packet->dts;
    //samples_stats_log(CATEGORY_RECEIVER,AV_LOG_DEBUG,&ctx->receiverStats,session->stream_name);
    return packet_queue_write_packet(&ctx->packetQueue, packet);
}

void transcode_session_get_ack_frame_id(transcode_session_t *ctx,kmp_frame_position_t *pos)
{
    if(ctx->ack_handler){
       pos->frame_id = ctx->ack_handler->lastMappedAck;
       pos->offset = ctx->ack_handler->lastOffset;
       pos->transcoded_frame_id = ctx->ack_handler->lastAck;
    }
}

int transcode_session_set_media_info(transcode_session_t *ctx,transcode_mediaInfo_t* newMediaInfo)
{
    if (ctx->currentMediaInfo) {
        bool changed = false;
        if(ctx->currentMediaInfo != newMediaInfo) {
            AVCodecParameters *currentCodecParams=ctx->currentMediaInfo->codecParams;
            AVCodecParameters *newCodecParams=newMediaInfo->codecParams;
            changed=newCodecParams->width!=currentCodecParams->width ||
                newCodecParams->height!=currentCodecParams->height ||
                newCodecParams->extradata_size!=currentCodecParams->extradata_size;

            if (currentCodecParams->extradata_size>0 &&
                newCodecParams->extradata!=NULL &&
                currentCodecParams->extradata!=NULL
                // FIXME: uncomment memcp!!!
                && ctx->processedStats.totalFrames > 0
                /*&& 0!=memcmp(newCodecParams->extradata,currentCodecParams->extradata,currentCodecParams->extradata_size)*/)
                changed=true;
        }

        if (!changed) {

            avcodec_parameters_free(&newMediaInfo->codecParams);
            av_free(newMediaInfo);
            return 0;
        } else {

            LOGGER0(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"changing media info on the fly is currently not supported");
            return -1;
        }
    }

    ctx->currentMediaInfo=newMediaInfo;

    transcode_codec_t *pDecoderContext=&ctx->decoder[0];
    transcode_codec_init_decoder(pDecoderContext,newMediaInfo);
    sprintf(pDecoderContext->name,"Decoder for input %s",ctx->name);
    ctx->decoders++;
    if (init_outputs_from_config(ctx)<0) {
        LOGGER0(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"init_outputs_from_config failed");
        exit(-1);
    }

    for (int outputId=0;outputId<ctx->outputs && !ctx->ack_handler;outputId++) {
         if(!ctx->output[outputId].passthrough) {
              LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"transcode_session_set_media_info set ack_handler for output %d",outputId);
              ctx->ack_handler = &ctx->output[outputId];
               _S(ack_hanler_create(ctx->input_frame_first_id,
                       ctx->transcoded_frame_first_id,
                       ctx->ack_handler->track_id,
                       pDecoderContext->ctx->codec_type,
                       &ctx->ack_handler->acker));
         }
    }

    if(pDecoderContext->ctx->codec_type == AVMEDIA_TYPE_VIDEO){
        _S(atsc_a53_handler_create(&ctx->cc_a53));
    }

    if(ctx->outputs && !ctx->ack_handler)
        ctx->ack_handler = &ctx->output[0];
    return 0;
}

void get_filter_config(transcode_session_t *pSession,char *filterConfig,  transcode_codec_t *pDecoderContext, transcode_session_output_t *pOutput)
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
        //once initialized stick to encoder output format
        transcode_codec_t *codec = pOutput->actualAudioParams.samplingRate > 0 ?
            &pSession->encoder[pOutput->encoderId] : pDecoderContext;
        char buf[64];
        av_get_channel_layout_string(buf,sizeof(buf),
            codec->ctx->channels,codec->ctx->channel_layout);
        sprintf(filterConfig,"aresample=async=0:out_sample_rate=%d:out_channel_layout=%s",
            codec->ctx->sample_rate,buf);
    }
}

transcode_filter_t* GetFilter(transcode_session_t* pContext,transcode_session_output_t* pOutput, transcode_codec_t *pDecoderContext)
{
    char filterConfig[MAX_URL_LENGTH]={0};
    get_filter_config(pContext,filterConfig, pDecoderContext, pOutput);

    transcode_filter_t* pFilter=NULL;
    pOutput->filterId=-1;
    for (int selectedFilter=0; selectedFilter<pContext->filters;selectedFilter++) {
        pFilter=&pContext->filter[selectedFilter];
        if (pFilter->config && strcmp(pFilter->config,filterConfig)==0) {
            pOutput->filterId=selectedFilter;
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Output %s - Resuing existing filter %s",pOutput->track_id,filterConfig);
            break;
        }
    }
    if ( pOutput->filterId==-1) {
        pFilter=&pContext->filter[pContext->filters];
        int ret=transcode_filter_init(pFilter,pDecoderContext->ctx,filterConfig);
        if (ret<0) {
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"Output %s - Cannot create filter %s",pOutput->track_id,filterConfig);
            return NULL;
        }

        pOutput->filterId=pContext->filters++;
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Output %s - Created new  filter %s",pOutput->track_id,filterConfig);
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

        pOutput->actualVideoParams.width=pEncoderContext->ctx->width;
        pOutput->actualVideoParams.height=pEncoderContext->ctx->height;

    }
    if (pOutput->codec_type==AVMEDIA_TYPE_AUDIO)
    {
        ret=transcode_codec_init_audio_encoder(pEncoderContext, pFilter,pOutput);
        pOutput->actualAudioParams.samplingRate=pEncoderContext->ctx->sample_rate;
        pOutput->actualAudioParams.channels=pEncoderContext->ctx->channels;
    }

    sprintf(pEncoderContext->name,"Encoder for output %s",pOutput->track_id);
    return ret;
}

static
int transcode_session_init_output(transcode_session_t* pContext,
    transcode_codec_t *pDecoderContext,
    transcode_session_output_t* pOutput)
{
    transcode_filter_t* pFilter=GetFilter(pContext,pOutput,pDecoderContext);
    transcode_codec_t* pEncoderContext=&pContext->encoder[pContext->encoders];

    _S(config_encoder(pOutput, pDecoderContext, pFilter, pEncoderContext));

    pOutput->encoderId=pContext->encoders++;
    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Output %s - Added encoder %d bitrate=%d",pOutput->track_id,pOutput->encoderId,pOutput->bitrate);
    transcode_mediaInfo_t extra;
    extra.frameRate=pEncoderContext->ctx->framerate;
    extra.timeScale=pEncoderContext->ctx->time_base;
    extra.codecParams=avcodec_parameters_alloc();
    //TODO: how do we know encoder supports captions?
    extra.closed_captions = pContext->currentMediaInfo->closed_captions;
    avcodec_parameters_from_context(extra.codecParams,pEncoderContext->ctx);
    if(!extra.codecParams->bits_per_coded_sample) {
        extra.codecParams->bits_per_coded_sample = pDecoderContext->ctx->bits_per_coded_sample;
    }
    _S(transcode_session_output_set_media_info(pOutput,&extra));
    if(pEncoderContext->codec->type == AVMEDIA_TYPE_VIDEO) {
         _S(atsc_a53_add_stream(pContext->cc_a53,pEncoderContext->ctx,pOutput->encoderId));
    }


    return 0;
}

int transcode_session_add_output(transcode_session_t* pContext, const json_value_t* json )
{
    transcode_session_output_t* pOutput=&pContext->output[pContext->outputs++];
    transcode_session_output_from_json(pOutput, json);
    strcpy(pOutput->channel_id,pContext->channelId);
    int ret=0;
    _S(transcode_session_output_connect(pOutput,
        pOutput->passthrough ? pContext->input_frame_first_id : pContext->transcoded_frame_first_id));
    if (pOutput->passthrough)
    {
        _S(transcode_session_output_set_media_info(pOutput,pContext->currentMediaInfo));
    }

    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Added output %s  passthrough=%d",pOutput->track_id,pOutput->passthrough);

    return 0;
}


/* processing */
int encodeFrame(transcode_session_t *pContext,int encoderId,int outputId,AVFrame *pFrame) {

    transcode_codec_t* pEncoder=&pContext->encoder[encoderId];
    transcode_session_output_t* pOutput=&pContext->output[outputId];
    frame_id_t output_frame_id;

    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG, "[%s] Sending packet %s to encoderId %d",
           pOutput->track_id,
           getFrameDesc(pFrame),
           encoderId);


    int ret=0;

    if (pFrame) {
        //key frame aligment
        if (pFrame->key_frame==1 || (pFrame->flags & AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY)
            pFrame->pict_type=AV_PICTURE_TYPE_I;
        else
            pFrame->pict_type=AV_PICTURE_TYPE_NONE;

    }

    ret=transcode_encoder_send_frame(pEncoder,pFrame);
encoder_error:
    if (ret < 0)
    {
          LOGGER(CATEGORY_TRANSCODING_SESSION, AV_LOG_ERROR,"Error during encoding %d (%s)",ret,av_err2str(ret))
          ret = pContext->policy.handle_error(&pContext->policy,ret);
          if (ret < 0)
            return ret;
    }
    while (ret >= 0) {
        AVPacket *pOutPacket = av_packet_alloc();

        ret = transcode_encoder_receive_packet(pEncoder,pOutPacket);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {

            if (ret == AVERROR_EOF) {
                LOGGER0(CATEGORY_TRANSCODING_SESSION, AV_LOG_INFO,"encoding completed!")
            }
            av_packet_free(&pOutPacket);
            return 0;
        }
        else if (ret < 0)
        {
            goto encoder_error;
        }

        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] received encoded frame %s from encoder Id %d",
               pOutput->track_id,
               getPacketDesc(pOutPacket),
               encoderId);
        output_frame_id = pContext->transcoded_frame_first_id+pOutput->stats.totalFrames;
        add_packet_frame_id_and_pts(pOutPacket,output_frame_id,pOutPacket->pts);

        pOutPacket->pos=clock_estimator_get_clock(&pContext->clock_estimator,pOutPacket->dts);

        if(pContext->ack_handler == pOutput){
            _S(ackEncode(pEncoder->ctx,&pContext->ack_handler->acker,pOutPacket));
        }
        if(pEncoder->codec->type == AVMEDIA_TYPE_VIDEO) {
             atsc_a53_encoded(pContext->cc_a53,pOutput->encoderId,&pOutPacket);
        }
        ret = transcode_session_output_send_output_packet(pOutput,pOutPacket);

       av_packet_free(&pOutPacket);
    }
    return ret;
}

static
bool mediaTypesMatch(transcode_filter_t *pFilter,AVCodecContext *ctx)
{
    if(ctx->codec_type == AVMEDIA_TYPE_AUDIO)
    {
        uint64_t channelLayout=ctx->channel_layout;
        if (channelLayout<=0) {
             channelLayout=av_get_default_channel_layout(ctx->channels);
        }
        return ctx->sample_fmt == pFilter->src_ctx->outputs[0]->format
            && channelLayout == pFilter->src_ctx->outputs[0]->channel_layout
            && ctx->channels == pFilter->src_ctx->outputs[0]->channels
            && ctx->sample_rate == pFilter->src_ctx->outputs[0]->sample_rate;
    }
    // video
    //TODO: get more video related props to compare
    return ctx->width == pFilter->src_ctx->outputs[0]->w
       && ctx->height == pFilter->src_ctx->outputs[0]->h
       && ctx->sample_fmt ==  pFilter->src_ctx->outputs[0]->format;
}

static
bool mediaTypesMatchWithFrame(transcode_filter_t *pFilter,AVFrame *pFrame)
{
    if(pFilter->src_ctx->outputs[0]->type == AVMEDIA_TYPE_AUDIO)
    {
        uint64_t channelLayout=pFrame->channel_layout;
        if (channelLayout<=0) {
             channelLayout=av_get_default_channel_layout(pFrame->channels);
        }
        return pFrame->format == pFilter->src_ctx->outputs[0]->format
            && channelLayout == pFilter->src_ctx->outputs[0]->channel_layout
            && pFrame->channels == pFilter->src_ctx->outputs[0]->channels
            && pFrame->sample_rate == pFilter->src_ctx->outputs[0]->sample_rate;
    }
    // video
    //TODO: get more video related props to compare
    return pFrame->width == pFilter->src_ctx->outputs[0]->w
       && pFrame->height == pFilter->src_ctx->outputs[0]->h
       && pFrame->format ==  pFilter->src_ctx->outputs[0]->format;
}


static
int getFilterForStream(transcode_session_t *pContext,int filterId,
  AVFrame *pFrame, transcode_codec_t* pDecoderContext,transcode_filter_t **ppFilter)
{
   *ppFilter = NULL;
   transcode_filter_t *pFilter =  &pContext->filter[filterId];
   if(pFrame ? mediaTypesMatchWithFrame(pFilter,pFrame) : mediaTypesMatch(pFilter,pDecoderContext->ctx))
   {
       *ppFilter = pFilter;
   }
   else
   {
      LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_WARNING,
        "decoder and filter media types don\'t match => reinit filter %d",filterId);

     // find output corresponding to filter
     transcode_session_output_t *pOutput = &pContext->output[0],
                                *sentinel = &pContext->output[pContext->outputs];
     for (;pOutput<sentinel;pOutput++)
     {
         if (pOutput->filterId==filterId && pOutput->encoderId!=-1)
         {
            int temp = pContext->filters;
            pContext->filters = filterId;
            // free filter
            transcode_filter_close(pFilter);
            pOutput->filterId = -1;
            // re-init filter
            *ppFilter = GetFilter(pContext,pOutput,pDecoderContext);
            if(*ppFilter)
            {
                av_buffersink_set_frame_size((*ppFilter)->sink_ctx, pContext->encoder[pOutput->encoderId].ctx->frame_size);
            }
            pContext->filters =  temp;
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"reinited filter %d",filterId);
            break;
         }
     }
   }
   return *ppFilter ? 0 : -1;
}

int sendFrameToFilter(transcode_session_t *pContext,int filterId, AVCodecContext* pDecoderContext, AVFrame *pFrame)
{
    transcode_filter_t *pFilter;
    int ret=getFilterForStream(pContext,filterId,pFrame,&pContext->decoder[0],&pFilter);
    if (ret<0) {
         LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"[%s] getFilterForStream failed for filterId %d (%s): %d (%s)",
                pContext->name,
                filterId,
                pContext->filter[filterId].config,
                ret,
                av_err2str(ret));
     }


    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] sending frame to filter %d (%s) %s",
           pContext->name,
           filterId,
           pContext->filter[filterId].config,
           getFrameDesc(pFrame));

    ret=transcode_filter_send_frame(pFilter,pFrame);
    if (ret<0) {

        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"[%s] failed sending frame to filterId %d (%s): %s %d (%s)",
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
            goto filter_error;
        }


        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] recieved from filterId %d (%s): %s",
               pContext->name,
               filterId,
               pContext->filter[filterId].config,getFrameDesc(pOutFrame))

        if(pContext->ack_handler && pContext->ack_handler->filterId == filterId ) {
             ackFilter(&pContext->ack_handler->acker,pOutFrame);
        }



        for (int outputId=0;outputId<pContext->outputs;outputId++) {
            transcode_session_output_t *pOutput=&pContext->output[outputId];
            if (pOutput->filterId==filterId && pOutput->encoderId!=-1){
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] sending frame from filterId %d to encoderId %d",pOutput->track_id,filterId,pOutput->encoderId);
               if(pDecoderContext->codec_type == AVMEDIA_TYPE_VIDEO) {
                  atsc_a53_filtered(pContext->cc_a53,pOutput->encoderId,pOutFrame);
               }
                _S(encodeFrame(pContext,pOutput->encoderId,outputId,pOutFrame));
            }
        }
        av_frame_free(&pOutFrame);
    }
filter_error:
    return 0;
}

static void shift_audio_samples(AVFrame *frame,int shift_by) {
  av_samples_copy(frame->extended_data, frame->extended_data, 0, shift_by,
       frame->nb_samples - shift_by, frame->channels, frame->format);
  frame->nb_samples -= shift_by;
}

int OnDecodedFrame(transcode_session_t *ctx,AVCodecContext* decoderCtx, AVFrame *frame)
{
   uint64_t pts;
   for (int outputId=0;outputId<ctx->outputs;outputId++) {
         transcode_session_output_t *pOutput=&ctx->output[outputId];
         if (!pOutput->passthrough && pOutput->encoderId==-1) {
              _S(transcode_session_init_output(ctx,&ctx->decoder[0],pOutput));
         }
    }

    if (frame==NULL) {

        for (int outputId=0;outputId<ctx->outputs;outputId++) {
            transcode_session_output_t *pOutput=&ctx->output[outputId];
            if (pOutput->encoderId!=-1){
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] flushing encoderId %d for output %s",ctx->name,pOutput->encoderId,pOutput->track_id);
                _S(encodeFrame(ctx,pOutput->encoderId,outputId,NULL));
            }
        }
        return 0;
    }

    // we do not rely on decoder timestamps since it does not
    // take into account arbitrary jumps.
    if(!get_frame_original_pts(frame,&pts)) {
        frame->pts = frame->pkt_dts = pts;
    }

    if(ctx->offset > 0){
        if(decoderCtx->codec_type == AVMEDIA_TYPE_AUDIO) {
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] decoded audio frame samples: %ld. offset: %ld",ctx->name,
                frame->nb_samples,ctx->offset);
            if(frame->nb_samples > ctx->offset) {
                // shift left by amount of offset
                int64_t offsetAsTime =  ff_samples_to_time_base(decoderCtx,ctx->offset);
                shift_audio_samples(frame,ctx->offset);
                ctx->offset = 0;
                frame->pts += offsetAsTime;
            } else {
                ctx->offset -= frame->nb_samples;
                return 0;
            }
        } else if(decoderCtx->codec_type == AVMEDIA_TYPE_VIDEO && ctx->offset > 0) {
            //offset designates # of prerolled frames
             ctx->offset--;
             return 0;
        }
    }

    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] decoded: %s",ctx->name,getFrameDesc(frame));

    if(decoderCtx->codec_type == AVMEDIA_TYPE_VIDEO) {
        atsc_a53_decoded(ctx->cc_a53,frame);
    }

    if (ctx->dropper.enabled && transcode_dropper_should_drop_frame(&ctx->dropper,ctx->lastQueuedDts,frame))
    {
        return 0;
    }

    if(ctx->ack_handler) {
         ackDecode(&ctx->ack_handler->acker,frame);
    }



    for (int filterId=0;filterId<ctx->filters;filterId++) {

        _S(sendFrameToFilter(ctx,filterId,decoderCtx,frame));

    }

    for (int outputId=0;outputId<ctx->outputs;outputId++) {
        transcode_session_output_t *pOutput=&ctx->output[outputId];
        if (pOutput->filterId==-1 && pOutput->encoderId!=-1){
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG,"[%s] sending frame directly from decoder to encoderId %d for output %s",ctx->name,pOutput->encoderId,pOutput->track_id);
            _S(encodeFrame(ctx,pOutput->encoderId,outputId,frame));
        }
    }

    return 0;
}

int decodePacket(transcode_session_t *transcodingContext,const AVPacket* pkt) {

    int ret;


    if (pkt!=NULL) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG, "[%s] Sending packet %s to decoder",
               transcodingContext->name,
               getPacketDesc(pkt));
    }
    transcode_codec_t* pDecoder=&transcodingContext->decoder[0];

    ret = transcode_decoder_send_packet(pDecoder, pkt);

    while (ret >= 0) {
        AVFrame *pFrame = av_frame_alloc();

        ret = transcode_decoder_receive_frame(pDecoder, pFrame);
        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            av_frame_free(&pFrame);
            if (ret == AVERROR_EOF) {
                LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"[%d] EOS from decode",0)
                _S(OnDecodedFrame(transcodingContext,pDecoder->ctx,NULL));
            }
            return 0;
        }
        else if (ret < 0)
        {
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"[%d] Error during decoding %d (%s)",pkt->stream_index,ret,av_err2str(ret));
            break;
        }
        ret = OnDecodedFrame(transcodingContext,pDecoder->ctx,pFrame);
        if (ret < 0)
        {
            LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR,"[%d] Error OnDecodedFrame  %d (%s)",pkt->stream_index,ret,av_err2str(ret));
        }

        av_frame_free(&pFrame);
    }

    if (ret < 0) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_ERROR, "[%d] decoding error %d (%s)",pkt->stream_index,ret,av_err2str(ret));
        ret = transcodingContext->policy.handle_error(&transcodingContext->policy,ret);
    }
    return ret;
}

int transcode_session_send_packet(transcode_session_t *ctx ,struct AVPacket* packet)
{
    int ret = 0;
    if (packet!=NULL) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_DEBUG, "Processing packet %s",getPacketDesc(packet));
        clock_estimator_push_frame(&ctx->clock_estimator,packet->dts,packet->pos);
        ctx->lastInputDts=packet->dts;
        samples_stats_add(&ctx->processedStats,packet->dts,packet->pos,packet->size);
    }
    bool shouldDecode=false;
    for (int i=0;i<ctx->outputs;i++) {
        transcode_session_output_t *pOutput=&ctx->output[i];
        if (pOutput->passthrough)
        {
            _S(transcode_session_output_send_output_packet(pOutput,packet));
        }
        else
        {
            shouldDecode=true;
        }
    }
    if (shouldDecode) {

        if (packet==NULL || !ctx->dropper.enabled || !transcode_dropper_should_drop_packet(&ctx->dropper,ctx->lastQueuedDts,packet))
        {
            _S(decodePacket(ctx,packet));
        }
    }
    if (ctx->onProcessedFrame) {
        ctx->onProcessedFrame(ctx->onProcessedFrameContext,false);
    }
    return ret;
}


/* shutting down */

int transcode_session_close(transcode_session_t *session,int exitErrorCode) {

    if (session->packetQueue.queueSize>0) {
        packet_queue_destroy(&session->packetQueue);
    }

    if(exitErrorCode >= 0) {
        LOGGER0(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO, "Flushing started");
        transcode_session_send_packet(session,NULL);
        LOGGER0(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO, "Flushing completed");
    }

    for (int i=0;i<session->decoders;i++) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Closing decoder %d",i);
        transcode_codec_close(&session->decoder[i]);
    }
    for (int i=0;i<session->filters;i++) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Closing filter %d",i);
        transcode_filter_close(&session->filter[i]);
    }
    for (int i=0;i<session->encoders;i++) {
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Closing encoder %d",i);
        transcode_codec_close(&session->encoder[i]);
    }


    if (session->onProcessedFrame) {
        session->onProcessedFrame(session->onProcessedFrameContext,true);
    }

    for (int i=0;i<session->outputs;i++){
        LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"Closing output %s",session->output[i].channel_id);
        transcode_session_output_close(&session->output[i]);
    }
    if (session->currentMediaInfo) {
        avcodec_parameters_free(&session->currentMediaInfo->codecParams);
        av_free(session->currentMediaInfo);
        session->currentMediaInfo=NULL;
    }
    free_policy_provider(&session->policy);

    atsc_a53_handler_free(&session->cc_a53);

    return 0;
}

static
void transcode_session_get_pipeline_diagnostics(transcode_session_t *ctx,json_writer_ctx_t js){
    uint64_t totalDecoderErrors = 0, totalEncoderErrors = 0, totalFilterErrors = 0;

    for (int i=0;i<ctx->decoders;i++)
     {
         transcode_codec_t* context=&ctx->decoder[i];
         totalDecoderErrors += context->inStats.totalErrors + context->outStats.totalErrors;;
     }
     for (int i=0;i<ctx->encoders;i++)
     {
         transcode_codec_t* context=&ctx->encoder[i];
         totalEncoderErrors += context->inStats.totalErrors + context->outStats.totalErrors;
     }
     for (int i=0;i<ctx->filters;i++)
     {
          transcode_filter_t* context=&ctx->filter[i];
          totalFilterErrors += context->totalInErrors + context->totalOutErrors;
     }
     if(totalFilterErrors || totalEncoderErrors || totalDecoderErrors){
            if(totalDecoderErrors){
                JSON_SERIALIZE_INT("decoderErrors",totalDecoderErrors)
            }
            if(totalEncoderErrors){
                JSON_SERIALIZE_INT("encoderErrors",totalEncoderErrors)
            }
            if(totalFilterErrors){
                 JSON_SERIALIZE_INT("filterErrors",totalFilterErrors)
            }
      }
}

void transcode_session_get_diagnostics(transcode_session_t *ctx,json_writer_ctx_t js)
{
    int64_t now=av_rescale_q( getClock64(), clockScale, standard_timebase);

    JSON_SERIALIZE_OBJECT_BEGIN("processed");
    sample_stats_get_diagnostics(&ctx->processedStats,js);
    JSON_SERIALIZE_OBJECT_END()

    /*
    JSON_SERIALIZE_ARRAY_START("decoders")
    for (int i=0;i<ctx->decoders;i++)
    {
        transcode_codec_t* context=&ctx->decoder[i];
        transcode_codec_get_diagnostics(context,js);
        JSON_SERIALIZE_ARRAY_ITEM()
    }
    JSON_SERIALIZE_ARRAY_END()
    JSON_SERIALIZE_ARRAY_START("encoders")
    for (int i=0;i<ctx->encoders;i++)
    {
        transcode_codec_t* context=&ctx->encoder[i];
        transcode_codec_get_diagnostics(context,js);
        JSON_SERIALIZE_ARRAY_ITEM()
    }
    JSON_SERIALIZE_ARRAY_END()
     */
    JSON_SERIALIZE_ARRAY_START("outputs")

    uint64_t lastDts=UINT64_MAX;
    uint64_t lastTimeStamp=UINT64_MAX;

    for (int i=0;i<ctx->outputs;i++)
    {
        transcode_session_output_t* output=&ctx->output[i];
        if (lastTimeStamp>output->stats.lastTimeStamp) {
            lastDts=output->stats.lastDts;
            lastTimeStamp=output->stats.lastTimeStamp;
        }
        transcode_session_output_get_diagnostics(output,ctx->lastQueuedDts,ctx->processedStats.lastDts,js);
        JSON_SERIALIZE_ARRAY_ITEM();
    }
    JSON_SERIALIZE_ARRAY_END()

    JSON_SERIALIZE_INT64("lastIncomingDts",ctx->lastQueuedDts);
    JSON_SERIALIZE_INT64("lastProcessedDts",ctx->processedStats.lastDts);
    JSON_SERIALIZE_INT64("minDts",lastDts);
    JSON_SERIALIZE_INT64("processTime",(ctx->lastInputDts-lastDts)/90);
    JSON_SERIALIZE_INT64("latency",(now-lastTimeStamp)/90);
    JSON_SERIALIZE_INT("currentIncomingQueueLength",ctx->packetQueue.queue ? av_thread_message_queue_nb_elems(ctx->packetQueue.queue) : -1);

    transcode_session_get_pipeline_diagnostics(ctx,js);
}
