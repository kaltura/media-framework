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

enum TranscodeOutputType
{
    TranscodeOutputType_Video,
    TranscodeOutputType_Audio
};


typedef struct
{
    char set_id[MAX_SET_ID];
    char track_id[MAX_TRACK_ID];
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
    
    struct
    {
        int samplingRate, channels;
    } audioParams;
    
    int filterId;
    int encoderId;
    
    samples_stats_t stats;
    
    AVFormatContext *oc;
    AVBSFContext* bsf;
    
    KMP_session_t* sender;
} transcode_session_output_t;


int transcode_session_output_init(transcode_session_output_t* ) ;
int transcode_session_output_from_json(transcode_session_output_t* ,const json_value_t* );
int transcode_session_output_close(transcode_session_output_t* ) ;

int transcode_session_output_set_format(transcode_session_output_t *,struct AVCodecParameters* ,AVRational ) ;
int transcode_session_output_send_output_packet(transcode_session_output_t *,struct AVPacket* ) ;

int transcode_session_output_get_diagnostics (transcode_session_output_t *,char* );

#endif /* output_h */


