//
//  filter.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 01/01/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef filter_h
#define filter_h

#include "core.h"

typedef  struct
{
    char* config;
    AVFilterGraph* filter_graph;
    AVFilterContext *sink_ctx;
    AVFilterContext *src_ctx;
} transcode_filter_t;

int transcode_filter_init( transcode_filter_t *pFilter, AVCodecContext *dec_ctx,const char *filters_descr);
int transcode_filter_send_frame( transcode_filter_t *pFilter,struct AVFrame* pInFrame);
int transcode_filter_receive_frame( transcode_filter_t *pFilter,struct AVFrame* pOutFrame);
int transcode_filter_close( transcode_filter_t *pFilter);

#endif /* filter_h */
