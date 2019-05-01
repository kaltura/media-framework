//
//  TranscoderEncoder.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 03/01/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//
#include "core.h"
#include "transcode_codec.h"
#include "utils.h"
#include "logger.h"
#include "config.h"

static enum AVPixelFormat hw_pix_fmt;

int transcode_codec_init( transcode_codec_t * pContext)
{
    pContext->name[0]=0;
    pContext->inPts=pContext->outPts=0;
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
            hw_pix_fmt = config->pix_fmt;
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
    LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Initializing CUDA frames context: sw_format = %s, width = %d, height = %d",
           av_get_pix_fmt_name(frames_ctx->sw_format), frames_ctx->width, frames_ctx->height);

    

    return ret;
}



static enum AVPixelFormat get_hw_format(AVCodecContext *ctx,const enum AVPixelFormat *pix_fmts)
{
    const enum AVPixelFormat *p;
    
    
    for (p = pix_fmts; *p != -1; p++) {
        if (*p == hw_pix_fmt) {
            LOGGER(CATEGORY_CODEC, AV_LOG_INFO, "get_hw_format returned %s",av_get_pix_fmt_name (hw_pix_fmt));
            return *p;
        }
    }
    
    LOGGER0(CATEGORY_CODEC, AV_LOG_ERROR, "Failed to get HW surface format");
    return AV_PIX_FMT_NONE;
}


static int get_decoder_buffer(AVCodecContext *s, AVFrame *frame, int flags)
{
    transcode_codec_t *context = s->opaque;
    
    
    return avcodec_default_get_buffer2(s, frame, flags);
}



int transcode_codec_init_decoder( transcode_codec_t * pContext,AVCodecParameters *pCodecParams,AVRational framerate)
{
    transcode_codec_init(pContext);
    bool result;
    json_get_bool(GetConfig(),"engine.useNvidiaDecoder",false,&result);

    
    enum AVHWDeviceType hardWareAcceleration=AV_HWDEVICE_TYPE_NONE;
    
    pContext->nvidiaAccelerated=false;
    
    AVCodec *dec = NULL;
    if (result) {
        if (pCodecParams->codec_id==AV_CODEC_ID_H264) {
            dec = avcodec_find_decoder_by_name("h264_cuvid");
        }
        if (pCodecParams->codec_id==AV_CODEC_ID_HEVC) {
            dec = avcodec_find_decoder_by_name("h265_cuvid");
        }
        if (pCodecParams->codec_id==AV_CODEC_ID_VP8) {
            dec = avcodec_find_decoder_by_name("vp8_cuvid");
        }
        if (pCodecParams->codec_id==AV_CODEC_ID_VP9) {
            dec = avcodec_find_decoder_by_name("vp9_cuvid");
        }
        
        if (dec) {
            pContext->nvidiaAccelerated=true;
            hardWareAcceleration=AV_HWDEVICE_TYPE_CUDA;
        }
    }
    if (dec==NULL) {
        dec = avcodec_find_decoder(pCodecParams->codec_id);
    }

    pContext->codec=dec;

    AVCodecContext *codec_ctx;
    if (!dec) {
        LOGGER0(CATEGORY_CODEC,AV_LOG_ERROR, "Failed to find decoder for stream");
        return AVERROR_DECODER_NOT_FOUND;
    }
    codec_ctx = avcodec_alloc_context3(dec);
    if (!codec_ctx) {
        LOGGER0(CATEGORY_CODEC,AV_LOG_ERROR, "Failed to allocate the decoder context for stream");
        return AVERROR(ENOMEM);
    }
    codec_ctx->opaque=pContext;
    codec_ctx->framerate=framerate;
    
    codec_ctx->time_base=standard_timebase;

    int ret = avcodec_parameters_to_context(codec_ctx, pCodecParams);
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Failed to copy decoder parameters to input decoder context for stream  %d (%s)",ret,av_err2str(ret));
        return ret;
    }

    if (hardWareAcceleration!=AV_HWDEVICE_TYPE_NONE) {
        
        ret=hw_decoder_init(pContext,dec,codec_ctx,hardWareAcceleration);
        if (ret < 0) {
            LOGGER(CATEGORY_CODEC, AV_LOG_ERROR, "Couldn't genereate hwcontext %d (%s)",ret,av_err2str(ret));
            return ret;
        }
        codec_ctx->get_format  = get_hw_format;
        codec_ctx->get_buffer2 = get_decoder_buffer;
        codec_ctx->hw_device_ctx = av_buffer_ref(pContext->hw_device_ctx);
        //codec_ctx->pix_fmt=hw_pix_fmt;
    }
    av_opt_set_int(codec_ctx, "refcounted_frames", 1, 0);
    
    ret = avcodec_open2(codec_ctx, dec, NULL);
    if (ret < 0) {
        LOGGER( CATEGORY_CODEC, AV_LOG_ERROR, "Failed to open decoder for stream %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    if (pContext->hw_device_ctx!=NULL) {
        codec_ctx->hw_frames_ctx = av_buffer_ref(pContext->hw_frames_ctx);
    }
    pContext->ctx = codec_ctx;
    codec_ctx->time_base=standard_timebase;

    if (codec_ctx->codec_type==AVMEDIA_TYPE_VIDEO) {
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO, "Initialized video decoder \"%s\" color space: %s",dec->long_name, av_get_pix_fmt_name (codec_ctx->pix_fmt));
    }
    if (codec_ctx->codec_type==AVMEDIA_TYPE_AUDIO) {
        LOGGER(CATEGORY_CODEC,AV_LOG_INFO, "Initialized audio decoder \"%s\"",dec->long_name);
    }
    return 0;
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
    
    AVCodec *codec      = NULL;
    AVCodecContext *enc_ctx  = NULL;
    int ret = 0;
    
    
    codec = avcodec_find_encoder_by_name(pOutput->codec);
    if (!codec) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"Unable to find %s",pOutput->codec);
        return -1;
    }
    enc_ctx = avcodec_alloc_context3(codec);
    enc_ctx->height = height;
    enc_ctx->width = width;
    enc_ctx->sample_aspect_ratio = inputAspectRatio;
    enc_ctx->pix_fmt = inputPixelFormat;
    enc_ctx->bit_rate = 1000*pOutput->bitrate;
    enc_ctx->bit_rate_tolerance = pOutput->bitrate*100; //10%
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

    if (strlen(pOutput->videoParams.preset)>0) {
        av_opt_set(enc_ctx->priv_data, "preset",   pOutput->videoParams.preset, 0);
    }
    if (strlen(pOutput->videoParams.profile)>0) {
        av_opt_set(enc_ctx->priv_data, "profile", pOutput->videoParams.profile, 0);
    }
    if (strcmp(pOutput->codec,"libx264")==0) {
        av_opt_set(enc_ctx->priv_data, "x264-params", "nal-hrd=cbr:ratetol=10", AV_OPT_SEARCH_CHILDREN);
    }
    enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;
    
        
    ret = avcodec_open2(enc_ctx, codec,NULL);
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"error initilizing video encoder %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    
    pContext->codec=codec;
    pContext->ctx=enc_ctx;
    LOGGER(CATEGORY_CODEC,AV_LOG_INFO,"video encoder  \"%s\"  %dx%d %d Kbit/s %s initilaized",codec->long_name,enc_ctx->width,enc_ctx->height,enc_ctx->bit_rate/1000, av_get_pix_fmt_name (enc_ctx->pix_fmt));
    
    pContext->inPts=0;
    pContext->outPts=0;

    return 0;
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
    enc_ctx->time_base = av_buffersink_get_time_base(pFilter->sink_ctx);
    enc_ctx->flags |= AV_CODEC_FLAG_GLOBAL_HEADER;

    enc_ctx->bit_rate=pOutput->bitrate*1000;
    enc_ctx->pkt_timebase=standard_timebase;
    ret = avcodec_open2(enc_ctx, codec,NULL);
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR,"error initilizing video encoder %d (%s)",ret,av_err2str(ret));
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
int transcode_codec_send_frame( transcode_codec_t *encoder,const AVFrame* pFrame)
{
    if (pFrame!=NULL) {
        encoder->inPts=pFrame->pts;
        samples_stats_add(&encoder->inStats,pFrame->pts,0);
    }

    int ret = avcodec_send_frame(encoder->ctx, pFrame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return 0;
    }
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_WARNING, "Error sending a packet for encoding %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    return ret;
}
int transcode_codec_receive_packet( transcode_codec_t *encoder,AVPacket* pkt)
{
    int ret;
    ret = avcodec_receive_packet(encoder->ctx, pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return ret;
    }
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_WARNING, "Error recveiving a packet for encoding %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    encoder->outPts=pkt->pts;
    samples_stats_add(&encoder->outStats,pkt->pts,pkt->size);

    return ret;
    
}


int transcode_codec_send_packet( transcode_codec_t *decoder,const AVPacket* pkt) {
    
    int ret;
    
    //LOGGER0(CATEGORY_CODEC, AV_LOG_DEBUG,"Sending packet to decoder");
    
    if (pkt!=NULL) {
        decoder->inPts=pkt->pts;
        samples_stats_add(&decoder->inStats,pkt->pts,pkt->size);
    }
    ret = avcodec_send_packet(decoder->ctx, pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return 0;
    }
    if (ret < 0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "[%d] Error sending a packet to decoder %d (%s)",pkt->stream_index, ret,av_err2str(ret));
        return ret;
    }

    return 0;
    
}


int transcode_codec_receive_frame( transcode_codec_t *decoder,AVFrame *pFrame)
{
    int ret;
    ret = avcodec_receive_frame(decoder->ctx, pFrame);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
    {
        return ret;
    }
    if (ret<0) {
        LOGGER(CATEGORY_CODEC,AV_LOG_ERROR, "Error recieving packet from decoder %d (%s)",ret,av_err2str(ret));
        return ret;
    }
    //pFrame->pts = pFrame->best_effort_timestamp;
    
    
    decoder->outPts=pFrame->pts;
    samples_stats_add(&decoder->outStats,pFrame->pts,0);

    return 0;
}


int transcode_codec_get_diagnostics( transcode_codec_t *codec,char *buf)
{
    char tmp[2048];
    JSON_SERIALIZE_INIT(buf)
    JSON_SERIALIZE_STRING("name",codec->name)
    
    JSON_SERIALIZE_OBJECT_BEGIN("input")
        sample_stats_get_diagnostics(&codec->inStats, tmp);
        JSON_SERIALIZE_INT64("pts", codec->inPts)
        JSON_SERIALIZE_OBJECT("stats", tmp)
    JSON_SERIALIZE_OBJECT_END()
    
    JSON_SERIALIZE_OBJECT_BEGIN("output")
        sample_stats_get_diagnostics(&codec->outStats, tmp);
        JSON_SERIALIZE_INT64("pts", codec->outPts)
        JSON_SERIALIZE_OBJECT("stats", tmp)
    JSON_SERIALIZE_OBJECT_END()
    JSON_SERIALIZE_INT64("delay", codec->outPts-codec->inPts)

    JSON_SERIALIZE_END()
    return n;
}
