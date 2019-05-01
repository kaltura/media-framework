//
//  filter.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 01/01/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "transcode_filter.h"
#include "logger.h"

int transcode_filter_init( transcode_filter_t *pFilter, AVCodecContext *dec_ctx,const char *filters_descr)
{
    char args[512];
    int ret = 0;
    const AVFilter *buffersrc=NULL;
    const AVFilter *buffersink=NULL;
    
    
    if (dec_ctx->codec_type==AVMEDIA_TYPE_VIDEO) {
        buffersrc  = avfilter_get_by_name("buffer");
        buffersink = avfilter_get_by_name("buffersink");
        snprintf(args, sizeof(args),
                 "video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d:frame_rate=%d/%d:sws_param=%s",
                 dec_ctx->width, dec_ctx->height, dec_ctx->pix_fmt,
                 dec_ctx->time_base.num, dec_ctx->time_base.den,
                 dec_ctx->sample_aspect_ratio.num, dec_ctx->sample_aspect_ratio.den,
                 dec_ctx->framerate.num, dec_ctx->framerate.den,
                 "flags=2");
    }
    if (dec_ctx->codec_type==AVMEDIA_TYPE_AUDIO) {
        buffersrc  = avfilter_get_by_name("abuffer");
        buffersink = avfilter_get_by_name("abuffersink");
        snprintf(args, sizeof args,
                 "sample_rate=%d:sample_fmt=%d:channel_layout=0x%"PRIx64":channels=%d:"
                 "time_base=%d/%d",
                 dec_ctx->sample_rate, dec_ctx->sample_fmt, dec_ctx->channel_layout,
                 dec_ctx->channels, dec_ctx->time_base.num, dec_ctx->time_base.den);
    }
    
    AVFilterInOut *outputs = avfilter_inout_alloc();
    AVFilterInOut *inputs  = avfilter_inout_alloc();
           
    LOGGER(CATEGORY_FILTER,AV_LOG_INFO, "Create filter: config: \"%s\"  args: \"%s\"",filters_descr,args);

    pFilter->config=strdup(filters_descr);
    
    pFilter->filter_graph = avfilter_graph_alloc();
    if (!outputs || !inputs || !pFilter->filter_graph) {
        ret = AVERROR(ENOMEM);
        goto end;
    }
    
    
    ret = avfilter_graph_create_filter(&pFilter->src_ctx, buffersrc, "in",
                                       args, NULL, pFilter->filter_graph);
    if (ret < 0) {
        LOGGER(CATEGORY_FILTER,AV_LOG_ERROR, "Cannot create buffer source %d (%s)",ret,av_err2str(ret))
        goto end;
    }
    
    
    
    if (dec_ctx->hw_frames_ctx!=NULL) {
        LOGGER0(CATEGORY_FILTER, AV_LOG_INFO, "Setting hardware device context")
        AVBufferSrcParameters *par = av_buffersrc_parameters_alloc();
        memset(par, 0, sizeof(*par));
        par->format = AV_PIX_FMT_NONE;
        par->hw_frames_ctx=dec_ctx->hw_frames_ctx;
        ret = av_buffersrc_parameters_set(pFilter->src_ctx, par);
        if (ret<0) {
            LOGGER(CATEGORY_FILTER, AV_LOG_ERROR, "Failed setting hardware device context %d (%s)",ret,av_err2str(ret))
            goto end;
        }
        av_freep(&par);
    }
    
    
    
    ret = avfilter_graph_create_filter(&pFilter->sink_ctx, buffersink, "out",
                                       NULL, NULL, pFilter->filter_graph);
    if (ret < 0) {
        LOGGER(CATEGORY_FILTER, AV_LOG_ERROR, "Cannot create buffer sink %d (%s)",ret,av_err2str(ret))
        goto end;
    }

    if (dec_ctx->codec_type==AVMEDIA_TYPE_VIDEO)
    {
        enum AVPixelFormat pix_fmts[] = { AV_PIX_FMT_CUDA, AV_PIX_FMT_NV12, AV_PIX_FMT_YUV420P, AV_PIX_FMT_NONE };
        ret = av_opt_set_int_list(pFilter->sink_ctx, "pix_fmts", pix_fmts,
                                  AV_PIX_FMT_NONE, AV_OPT_SEARCH_CHILDREN);
        if (ret < 0) {
            av_log(NULL, AV_LOG_ERROR, "Cannot set output pixel format\n");
            goto end;
        }
    }
        
    outputs->name       = av_strdup("in");
    outputs->filter_ctx = pFilter->src_ctx;
    outputs->pad_idx    = 0;
    outputs->next       = NULL;
    
    inputs->name       = av_strdup("out");
    inputs->filter_ctx = pFilter->sink_ctx;
    inputs->pad_idx    = 0;
    inputs->next       = NULL;
    
    if ((ret = avfilter_graph_parse_ptr(pFilter->filter_graph, filters_descr,
                                        &inputs, &outputs, NULL)) < 0)  {
        LOGGER(CATEGORY_FILTER, AV_LOG_ERROR, "Cannot parse graph filters_descr: \"%s\" %d (%s)",filters_descr,ret,av_err2str(ret))
        goto end;
    }
    
    if (dec_ctx->hw_frames_ctx!=NULL) {
        for (int i = 0; i < pFilter->filter_graph->nb_filters; i++) {
            pFilter->filter_graph->filters[i]->hw_device_ctx = av_buffer_ref(dec_ctx->hw_frames_ctx);
        }
    }
        
    if ((ret = avfilter_graph_config(pFilter->filter_graph, NULL)) < 0) {
        
        LOGGER(CATEGORY_FILTER, AV_LOG_ERROR, "Cannot config graph filters_descr: \"%s\" %d (%s)",filters_descr,ret,av_err2str(ret))
        goto end;
    }
    
end:
    avfilter_inout_free(&inputs);
    avfilter_inout_free(&outputs);
    
    return ret;
}
int transcode_filter_close( transcode_filter_t *pFilter)
{
    avfilter_graph_free(&pFilter->filter_graph);
    return 0;
}

int transcode_filter_send_frame( transcode_filter_t *pFilter,struct AVFrame* pInFrame)
{
    int ret=0;
    ret = av_buffersrc_write_frame(pFilter->src_ctx, pInFrame);
    return ret;
}


int transcode_filter_receive_frame( transcode_filter_t *pFilter,struct AVFrame* pOutFrame)
{
    int ret=0;
    ret = av_buffersink_get_frame(pFilter->sink_ctx, pOutFrame);
    return ret;
}


