//
//  TranscoderEncoder.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 03/01/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//
#include "core.h"
#include "transcode_codec.h"


int transcode_codec_init( transcode_codec_t * pContext)
{
    pContext->name[0]=0;
    pContext->inDts=pContext->outDts=0;
    sample_stats_init(&pContext->inStats,standard_timebase);
    sample_stats_init(&pContext->outStats,standard_timebase);
    return 0;
}

static int hw_decoder_init( transcode_codec_t * pContext,AVCodec* decoder,AVCodecContext *ctx, const enum AVHWDeviceType type)
{
    LOGGER0(CATEGORY_CODEC,AV_LOG_INFO, "Intialize hardware device");

    for (int i = 0;; i++) {
        const AVCodecHWConfig *config = avcodec_get_hw_config(decoder, i);
        if (!config) {
            LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "Decoder %s does not support device type",decoder->name);
            return -1;
        }
        if (config->methods & AV_CODEC_HW_CONFIG_METHOD_HW_DEVICE_CTX &&
            config->device_type == type) {
            ctx->pix_fmt = config->pix_fmt;
            break;
        }
    }
    
    
    int ret = 0;
    
    if ((ret = av_hwdevice_ctx_create(&pContext->hw_device_ctx, type, NULL, NULL, 0)) < 0) {
        LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Failed to create specified HW device %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    
    pContext->hw_frames_ctx = av_hwframe_ctx_alloc(pContext->hw_device_ctx);
    if (!pContext->hw_frames_ctx) {
        LOGGER0(CATEGORY_CODEC, AV_LOG_ERROR, "Error creating a CUDA frames context");
        return AVERROR(ENOMEM);
    }
    
    AVHWFramesContext * frames_ctx = (AVHWFramesContext*)pContext->hw_frames_ctx->data;
    
    frames_ctx->format = AV_PIX_FMT_CUDA;
    frames_ctx->sw_format = AV_PIX_FMT_NV12;
    frames_ctx->width = ctx->width;
    frames_ctx->height = ctx->height;
    
    
    ret = av_hwframe_ctx_init(pContext->hw_frames_ctx);
    LOGGER(CATEGORY_CODEC, AV_LOG_INFO, "Initializing CUDA frames context: sw_format = %s, width = %d, height = %d",
           av_get_pix_fmt_name(frames_ctx->sw_format), frames_ctx->width, frames_ctx->height);

    

    return ret;
}



static enum AVPixelFormat get_hw_format(AVCodecContext *ctx,const enum AVPixelFormat *pix_fmts)
{
    const enum AVPixelFormat *p;
    
    
    for (p = pix_fmts; *p != -1; p++) {
        if (*p == ctx->pix_fmt) {
            LOGGER(CATEGORY_CODEC, AV_LOG_INFO, "get_hw_format returned %s",av_get_pix_fmt_name (*p));
            return *p;
        }
    }
    
    LOGGER0(CATEGORY_CODEC, AV_LOG_ERROR, "Failed to get HW surface format");
    return AV_PIX_FMT_NONE;
}


static int get_decoder_buffer(AVCodecContext *s, AVFrame *frame, int flags)
{
    //transcode_codec_t *context = s->opaque;
    
    return avcodec_default_get_buffer2(s, frame, flags);
}



int transcode_codec_init_decoder( transcode_codec_t * pContext,transcode_mediaInfo_t* extraParams)
{
    transcode_codec_init(pContext);

    AVCodecParameters *pCodecParams=extraParams->codecParams;
    
    enum AVHWDeviceType hardWareAcceleration=AV_HWDEVICE_TYPE_NONE;

   AVCodec *dec;

   bool result;
   json_get_bool(GetConfig(),"engine.nvidiaAccelerated",true,&result);

   pContext->nvidiaAccelerated = result && pCodecParams->codec_type == AVMEDIA_TYPE_VIDEO;

 retry:

#define FALLBACK_SW_DECODER \
    if( pContext->nvidiaAccelerated ) { \
            pContext->nvidiaAccelerated = false; \
            hardWareAcceleration = AV_HWDEVICE_TYPE_NONE; \
            goto retry;\
    }

    dec = NULL;

    LOGGER(CATEGORY_CODEC,AV_LOG_INFO, "attempt to use %s decoder",  pContext->nvidiaAccelerated ? "nvidia hw" : "sw");

    dec = avcodec_find_decoder(pCodecParams->codec_id);

    if (pContext->nvidiaAccelerated) {
       hardWareAcceleration=AV_HWDEVICE_TYPE_CUDA;
    }

    pContext->codec=dec;

    AVCodecContext *codec_ctx;
    if (!dec) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "Failed to find decoder for stream %s",pCodecParams->codec_id);
        FALLBACK_SW_DECODER;
        return AVERROR_DECODER_NOT_FOUND;
    }
    codec_ctx = avcodec_alloc_context3(dec);
    if (!codec_ctx) {
        LOGGER0(CATEGORY_CODEC,AV_LOG_ERROR, "Failed to allocate the decoder context for stream");
        return AVERROR(ENOMEM);
    }
    codec_ctx->opaque=pContext;
    codec_ctx->framerate=extraParams->frameRate;
    codec_ctx->time_base=extraParams->timeScale;
    codec_ctx->pkt_timebase=codec_ctx->time_base;

    int ret = avcodec_parameters_to_context(codec_ctx, pCodecParams);
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Failed to copy decoder parameters to input decoder context for stream  %d (%s)",ret,av_err2str(ret));
        return ret;
    }

    if (hardWareAcceleration!=AV_HWDEVICE_TYPE_NONE) {
        ret=hw_decoder_init(pContext,dec,codec_ctx,hardWareAcceleration);
        if (ret < 0) {
            LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Couldn't genereate hwcontext %d (%s)",ret,av_err2str(ret));
            FALLBACK_SW_DECODER;
            return ret;
        }
        codec_ctx->get_format  = get_hw_format;
        codec_ctx->get_buffer2 = get_decoder_buffer;
        codec_ctx->hw_device_ctx = av_buffer_ref(pContext->hw_device_ctx);
    }
    av_opt_set_int(codec_ctx, "refcounted_frames", 1, 0);
    
    ret = avcodec_open2(codec_ctx, dec, NULL);
    if (ret < 0) {
        LOGGER( CATEGORY_CODEC, AV_LOG_ERROR, "Failed to open decoder for stream %d (%s)",ret,av_err2str(ret));
        FALLBACK_SW_DECODER;
        return ret;
    }
    if (pContext->hw_device_ctx!=NULL) {
        codec_ctx->hw_frames_ctx = av_buffer_ref(pContext->hw_frames_ctx);
    }
    pContext->ctx = codec_ctx;
    //codec_ctx->time_base=extraParams->timeScale;
    if (codec_ctx->codec_type==AVMEDIA_TYPE_VIDEO) {
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO, "Initialized video decoder \"%s\" color space: %s width %d height %d ar %d/%d extra sz %d",
            dec->long_name, av_get_pix_fmt_name (codec_ctx->pix_fmt),
            codec_ctx->width,codec_ctx->height,
            codec_ctx->sample_aspect_ratio.num,
            codec_ctx->sample_aspect_ratio.den,
            codec_ctx->extradata_size);
    }
    if (codec_ctx->codec_type==AVMEDIA_TYPE_AUDIO) {
        char temp[128];
        av_get_channel_layout_string(temp,sizeof(temp),codec_ctx->channels,codec_ctx->channel_layout);
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO, "Initialized audio decoder \"%s\" %dHz %d bits - %s",dec->long_name,codec_ctx->sample_rate,codec_ctx->bits_per_coded_sample,temp);
    }
    return 0;
}

int get_preset(const char* codec,const char* preset,char* result,size_t resultSize) {
    char key[100]={0};
    sprintf(key,"engine.presets.%s.%s", preset,codec);
    if (JSON_OK==json_get_string(GetConfig(),key,preset,result, resultSize))
        return 0;
    return -1;
}

static
int
init_video_encoder(transcode_codec_t * pContext,
    transcode_session_output_t* pOutput,
     int width,
     int height,
     AVRational inputAspectRatio,
     enum AVPixelFormat inputPixelFormat,
     AVRational timebase,
     AVRational inputFrameRate,
     struct AVBufferRef* hw_frames_ctx,
     const char *codecName){

    int ret = 0;

    AVCodecContext *enc_ctx  = NULL;

    AVCodec *codec = avcodec_find_encoder_by_name(codecName);

    if (!codec) {
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"Unable to find %s",codecName);
        return -1;
    }

    enc_ctx = avcodec_alloc_context3(codec);
    enc_ctx->height = height;
    enc_ctx->width = width;
    enc_ctx->sample_aspect_ratio = inputAspectRatio;
    enc_ctx->pix_fmt = inputPixelFormat;
    enc_ctx->bit_rate = pOutput->bitrate;
    enc_ctx->bit_rate_tolerance = enc_ctx->bit_rate/10; //10%
    if (hw_frames_ctx!=NULL) {
        inputPixelFormat=AV_PIX_FMT_CUDA;
        enc_ctx->hw_frames_ctx = av_buffer_ref(hw_frames_ctx);
        if (!enc_ctx->hw_frames_ctx) {
            LOGGER0(CATEGORY_CODEC,AV_LOG_ERROR,"Coudln't create hw_frames_ctx");
            return -1;
        }
    }

    enc_ctx->gop_size=60;
    enc_ctx->time_base = timebase;
    enc_ctx->framerate = inputFrameRate;
    enc_ctx->pkt_timebase = timebase;

    if (strlen(pOutput->videoParams.profile)>0) {
        av_opt_set(enc_ctx->priv_data, "profile", pOutput->videoParams.profile, 0);
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"set video encoder profile %s",pOutput->videoParams.profile);
    }

    if(enc_ctx->codec_id == AV_CODEC_ID_H264) {
       // force key frame when input key frame arrive
       enc_ctx->gop_size=INT_MAX;
       av_opt_set_int(enc_ctx->priv_data, "forced-idr", 1, 0);
    }

    if (strlen(pOutput->videoParams.preset)>0) {
        char preset[100]={0};
        if (0>=get_preset(codec->name,pOutput->videoParams.preset,preset,sizeof(preset))) {
            av_opt_set(enc_ctx->priv_data, "preset",   preset, 0);
            LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"set video encoder preset %s",preset);
        }
    }
    if (strcmp(enc_ctx->codec->name,"libx264")==0) {
        av_opt_set(enc_ctx->priv_data, "x264-params", "nal-hrd=cbr:ratetol=10:scenecut=-1", AV_OPT_SEARCH_CHILDREN);
    }
    enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

    ret = avcodec_open2(enc_ctx, codec,NULL);
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"error initilizing video encoder %d (%s)",ret,av_err2str(ret));
        avcodec_free_context(&enc_ctx);
    } else {
        pContext->codec=codec;
        pContext->ctx=enc_ctx;
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"video encoder  \"%s\"  %dx%d %d Kbit/s %s initilaized",codec->long_name,enc_ctx->width,enc_ctx->height,enc_ctx->bit_rate/1000, av_get_pix_fmt_name (enc_ctx->pix_fmt));
    }
    return ret;
}
    
int transcode_codec_init_video_encoder( transcode_codec_t * pContext,
                       AVRational inputAspectRatio,
                       enum AVPixelFormat inputPixelFormat,
                       AVRational timebase,
                       AVRational inputFrameRate,
                       struct AVBufferRef* hw_frames_ctx,
                       const transcode_session_output_t* pOutput,
                       int width,int height)
{
    
    transcode_codec_init(pContext);
    

    int ret = -1;

    const json_value_t* result;
    char key[128];
    json_status_t status = JSON_OK;

    sprintf(key,"engine.encoders.%s", pOutput->codec);

    status= json_get(GetConfig(),key,&result);
    if (status!=JSON_OK) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"key %s not found",key);
        return ret;
    }

    size_t items=json_get_array_count(result);

    LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"got %d encoder codecs",items);

    for (int i=0; ret < 0 && i<items;i++) {

        json_value_t r;
        status=json_get_array_index(result,i,&r);
        if (status!=JSON_OK || r.type!=JSON_STRING) {
             LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"item %d is not a string???",i);
             continue;
        }

        char tmp[100]={0};
        memcpy(tmp,r.v.str.data,__MIN(sizeof(tmp)-1,r.v.str.len));

        LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"transcode_codec_init_video_encoder. checking encoder %s ",tmp);

        ret = init_video_encoder(pContext,
            pOutput,
            width,
            height,
            inputAspectRatio,
            inputPixelFormat,
            timebase,
            inputFrameRate,
            hw_frames_ctx,
            tmp);
    }

    return ret;
}

int transcode_codec_init_audio_encoder( transcode_codec_t * pContext,transcode_filter_t* pFilter, const  transcode_session_output_t* pOutput)
{
    transcode_codec_init(pContext);

    
    AVCodec *codec      = NULL;
    AVCodecContext *enc_ctx  = NULL;
    int ret = 0;
    
    
    codec = avcodec_find_encoder_by_name("aac");
    if (!codec) {
        LOGGER0(CATEGORY_CODEC,AV_LOG_ERROR,"Unable to find aac");
        return -1;
    }
    enc_ctx = avcodec_alloc_context3(codec);
    
    enc_ctx->sample_fmt = av_buffersink_get_format(pFilter->sink_ctx);
    enc_ctx->channel_layout = av_buffersink_get_channel_layout(pFilter->sink_ctx);
    enc_ctx->channels = av_buffersink_get_channels(pFilter->sink_ctx);
    enc_ctx->sample_rate = av_buffersink_get_sample_rate(pFilter->sink_ctx);
    enc_ctx->time_base = standard_timebase;// !
    enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    enc_ctx->bit_rate=pOutput->bitrate;
    ret = avcodec_open2(enc_ctx, codec,NULL);
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"error initilizing audio encoder %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    av_buffersink_set_frame_size(pFilter->sink_ctx, enc_ctx->frame_size);

    pContext->codec=codec;
    pContext->ctx=enc_ctx;
    LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"audio encoder  %dKhz %d Kbit/s initilaized",enc_ctx->sample_rate ,pOutput->bitrate);

    return 0;
}
int transcode_codec_close( transcode_codec_t * pContext)
{
    LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"closing codec '%s' total input = %ld output=%ld",
           pContext->name,
           pContext->inStats.totalFrames,
           pContext->outStats.totalFrames)
    avcodec_free_context(&pContext->ctx);
   // avcodec_close(pContext->ctx);
    //av_free(pContext->ctx);
    pContext->ctx=NULL;
    
    return 0;
}
int transcode_encoder_send_frame( transcode_codec_t *encoder, const AVFrame* pFrame)
{
    if (pFrame!=NULL) {
        encoder->inDts=pFrame->pts;
        samples_stats_add(&encoder->inStats,pFrame->pts,pFrame->pkt_pos, 0);
    }

    int ret = avcodec_send_frame(encoder->ctx, pFrame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return 0;
    }
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_WARNING, "Error sending a packet for encoding %d (%s)",ret,av_err2str(ret));
        encoder->inStats.totalErrors++;
        return ret;
    }
    return ret;
}
int transcode_encoder_receive_packet( transcode_codec_t *encoder,AVPacket* pkt)
{
    int ret;
    ret = avcodec_receive_packet(encoder->ctx, pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return ret;
    }
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_WARNING, "Error receiving a packet for encoding %d (%s)",ret,av_err2str(ret));
        encoder->outStats.totalErrors++;
        return ret;
    }

    encoder->outDts=pkt->dts;
    if (pkt->pos==-1) {
        pkt->pos=0;
    }
    samples_stats_add(&encoder->outStats,pkt->dts,pkt->pos,pkt->size);

    return ret;
    
}


int transcode_decoder_send_packet( transcode_codec_t *decoder, const AVPacket* pkt) {
    
    int ret;
    
    //LOGGER0(CATEGORY_CODEC, AV_LOG_DEBUG,"Sending packet to decoder");
    
    if (pkt!=NULL) {
        decoder->inDts=pkt->dts;
        samples_stats_add(&decoder->inStats,pkt->dts,pkt->pos,pkt->size);
    }
    ret = avcodec_send_packet(decoder->ctx, pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return 0;
    }
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "[%d] Error sending a packet to decoder %d (%s)",pkt->stream_index, ret,av_err2str(ret));
        decoder->inStats.totalErrors++;
        return ret;
    }

    return 0;
    
}


int transcode_decoder_receive_frame( transcode_codec_t *decoder,AVFrame *pFrame)
{
    int ret;
    ret = avcodec_receive_frame(decoder->ctx, pFrame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return ret;
    }
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "Error recieving packet from decoder %d (%s)",ret,av_err2str(ret));
        decoder->outStats.totalErrors++;
        return ret;
    }
    
    //pFrame->pts = pFrame->best_effort_timestamp;
    log_frame_side_data(CATEGORY_CODEC,pFrame);
    
    pFrame->pts = FFMAX(decoder->outDts+1,pFrame->pts);
    decoder->outDts=pFrame->pts;
    samples_stats_add(&decoder->outStats,pFrame->pts,pFrame->pkt_pos,0);

    return 0;
}


void transcode_codec_get_diagnostics( transcode_codec_t *codec,json_writer_ctx_t js)
{
    JSON_SERIALIZE_SCOPE_BEGIN();
        JSON_SERIALIZE_STRING("name",codec->name)
        JSON_SERIALIZE_OBJECT_BEGIN("input")
            JSON_SERIALIZE_OBJECT_BEGIN("stats")
              sample_stats_get_diagnostics(&codec->inStats,js);
            JSON_SERIALIZE_OBJECT_END()
            JSON_SERIALIZE_INT64("dts", codec->inDts)
        JSON_SERIALIZE_OBJECT_END()
        JSON_SERIALIZE_OBJECT_BEGIN("output")
             JSON_SERIALIZE_OBJECT_BEGIN("stats")
               sample_stats_get_diagnostics(&codec->outStats,js);
             JSON_SERIALIZE_OBJECT_END()
             JSON_SERIALIZE_INT64("dts", codec->outDts)
        JSON_SERIALIZE_OBJECT_END()
        JSON_SERIALIZE_INT64("delay", codec->outDts-codec->inDts)
   JSON_SERIALIZE_END()
}
