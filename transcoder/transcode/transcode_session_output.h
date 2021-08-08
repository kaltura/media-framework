//
//  output.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 31/12/2018.
//  Copyright © 2018 Kaltura. All rights reserved.
//

#ifndef output_h
#define output_h

#include "core.h"
#include "samples_stats.h"
#include "json_parser.h"
#include "KMP.h"
#include "../ackHandler/ackHandler.h"

enum TranscodeOutputType
{
    TranscodeOutputType_Video,
    TranscodeOutputType_Audio
};

typedef struct
{
    char channel_id[KMP_MAX_CHANNEL_ID];
    char track_id[KMP_MAX_TRACK_ID];
    char codec[128];
    enum AVMediaType codec_type;
    bool passthrough;
    int bitrate;
    struct VideoParams
    {
        int width,height;
        int frameRate;
        char profile[128];
        char level[128];
        char preset[128];
        int skipFrame;
    } videoParams;
    struct ActualVideoParams
    {
        int width,height;
    } actualVideoParams;
    
    struct AudioParams
    {
        int samplingRate, channels;
    } audioParams;
    struct ActualAudioParams
    {
        int samplingRate,channels;
    } actualAudioParams;
    
    int filterId;
    int encoderId;
    
    samples_stats_t stats;
    
    uint64_t fileDuration;
    uint64_t lastFileDts;
    AVFormatContext *oc;
    
    uint64_t lastAck;
    uint64_t lastMappedAck;
    uint32_t lastOffset;
    KMP_session_t* sender;
    // ack mapping
    ack_handler_t acker;
} transcode_session_output_t;


int transcode_session_output_init(transcode_session_output_t* ) ;
int transcode_session_output_from_json(transcode_session_output_t* ,const json_value_t* );
int transcode_session_output_close(transcode_session_output_t* ) ;

int transcode_session_output_connect(transcode_session_output_t *pOutput,uint64_t initial_frame_id);
int transcode_session_output_set_media_info(transcode_session_output_t *,transcode_mediaInfo_t* extra) ;
int transcode_session_output_send_output_packet(transcode_session_output_t *,struct AVPacket* ) ;

void transcode_session_output_get_diagnostics (transcode_session_output_t *,uint64_t recieveDts,uint64_t startProcessDts,json_writer_ctx_t js);

#endif /* output_h */


