//
//  TranscodePipeline.hpp
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#ifndef TranscodePipeline_hpp
#define TranscodePipeline_hpp


#include "transcode_session_output.h"
#include "transcode_codec.h"
#include "transcode_filter.h"
#include "../utils/time_estimator.h"
#include "../utils/packetQueue.h"
#include "./transcode_dropper.h"
#include "../utils/policy_provider.h"
#include "../utils/cc_atsc_a53.h"

#define MAX_INPUTS 10
#define MAX_OUTPUTS 10


typedef int transcode_session_processedFrameCB(void *pContext,bool completed);

typedef struct  {

    char name[KMP_MAX_CHANNEL_ID+KMP_MAX_TRACK_ID+2];
    char channelId[KMP_MAX_CHANNEL_ID];
    char trackId[KMP_MAX_TRACK_ID];
    transcode_mediaInfo_t* currentMediaInfo;

    int decoders;
    transcode_codec_t decoder[MAX_INPUTS];


    int outputs;
    transcode_session_output_t output[MAX_OUTPUTS];

    int encoders;
    transcode_codec_t encoder[MAX_OUTPUTS];


    int filters;
    transcode_filter_t filter[10];

    clock_estimator_t clock_estimator;

    uint64_t lastInputDts,lastQueuedDts;

    PacketQueueContext_t packetQueue;
    samples_stats_t processedStats;

    int64_t queueDuration;
    void* onProcessedFrameContext;
    transcode_session_processedFrameCB* onProcessedFrame;
    transcode_dropper_t dropper;
    frame_id_t input_frame_first_id,
               transcoded_frame_first_id;
    uint32_t   offset;
    transcode_session_output_t *ack_handler;
    policy_provider_s policy;
    atsc_a53_handler_t cc_a53;
} transcode_session_t;


/*
 0
 1
 */

int transcode_session_init(transcode_session_t *ctx,char* channelId,char* trackId,kmp_frame_position_t *initial_pos);
int transcode_session_set_media_info(transcode_session_t *pContext,transcode_mediaInfo_t* mediaInfo);
int transcode_session_send_packet(transcode_session_t *pContext, struct AVPacket* packet);

int transcode_session_async_set_mediaInfo(transcode_session_t *pContext,transcode_mediaInfo_t* mediaInfo);
int transcode_session_async_send_packet(transcode_session_t *pContext, struct AVPacket* packet);

int transcode_session_close(transcode_session_t *ctx,int exitErrorCode);
int transcode_session_add_output(transcode_session_t* pContext,const json_value_t* json);
void transcode_session_get_diagnostics(transcode_session_t *ctx,json_writer_ctx_t js);
void transcode_session_get_ack_frame_id(transcode_session_t *ctx,kmp_frame_position_t *pos);

#endif /* TranscodePipeline_hpp */
