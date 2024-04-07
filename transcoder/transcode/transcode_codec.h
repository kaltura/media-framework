//
//  TranscoderEncoder.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 03/01/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef TranscoderEncoder_h
#define TranscoderEncoder_h

#include <stdio.h>
#include "transcode_session_output.h"
#include "samples_stats.h"

typedef struct {
    char name[256];
    AVBufferRef *hw_device_ctx,*hw_frames_ctx;
    AVCodec* codec;
    AVCodecContext* ctx;
    int64_t inDts,outDts;
    bool nvidiaAccelerated;
    samples_stats_t inStats,outStats;

} transcode_codec_t;

#include "transcode_filter.h"


int transcode_codec_init(transcode_codec_t * pContext);

int transcode_codec_init_decoder(transcode_codec_t * pContext,transcode_mediaInfo_t* extraParams);

int transcode_codec_close(transcode_codec_t * pContext);

int transcode_codec_init_video_encoder(transcode_codec_t * pContext,
                       AVRational inputAspectRatio,
                       enum AVPixelFormat inputPixelFormat,
                       AVRational timebase,
                       AVRational inputFrameRate,
                       struct AVBufferRef* hw_frames_ctx,
                       const transcode_session_output_t* pOutput,
                       int width,int height);

int transcode_codec_init_audio_encoder(transcode_codec_t * pContext, transcode_filter_t* pFilter,const  transcode_session_output_t* pOutput);


int transcode_encoder_send_frame(transcode_codec_t *encoder, const AVFrame* pFrame);
int transcode_encoder_receive_packet(transcode_codec_t *encoder,AVPacket* pkt);

int transcode_decoder_send_packet( transcode_codec_t *decoder,const AVPacket* pkt);
int transcode_decoder_receive_frame( transcode_codec_t *decoder,AVFrame *pFrame);

int transcode_codec_reset( transcode_codec_t *decoder);

inline int64_t transcode_codec_get_latency( transcode_codec_t *codec) { return llabs(codec->outDts-codec->inDts);}

void transcode_codec_get_diagnostics( transcode_codec_t *decoder,json_writer_ctx_t js);

#endif /* TranscoderEncoder_h */
