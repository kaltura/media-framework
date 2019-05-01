//
//  TranscodePipeline.hpp
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#ifndef TranscodePipeline_hpp
#define TranscodePipeline_hpp


#include <libavutil/timestamp.h>
#include <libavformat/avformat.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include "transcode_session_output.h"
#include "transcode_codec.h"
#include "transcode_filter.h"

#define MAX_INPUTS 10
#define MAX_OUTPUTS 10


typedef struct  {
    
    char name[128];
    struct AVCodecParameters* inputCodecParams;
    
    int decoders;
    transcode_codec_t decoder[MAX_INPUTS];
    
    
    int outputs;
    transcode_session_output_t* output[MAX_OUTPUTS];
    
    int encoders;
    transcode_codec_t encoder[MAX_OUTPUTS];

    
    int filters;
    transcode_filter_t filter[10];
    
} transcode_session_t;


/*
 0
 1
 */

int transcode_session_init(transcode_session_t *ctx,char* name,struct AVCodecParameters* codecParams,AVRational framerate);
int transcode_session_send_packet(transcode_session_t *pContext, struct AVPacket* packet);
int transcode_session_close(transcode_session_t *ctx);
int transcode_session_add_output(transcode_session_t* pContext, transcode_session_output_t * pOutput);
int transcode_session_to_json(transcode_session_t *ctx,char* buf);

#endif /* TranscodePipeline_hpp */
