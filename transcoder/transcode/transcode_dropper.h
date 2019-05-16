//
//  transcode_dropper.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 14/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef transcode_dropper_h
#define transcode_dropper_h

#include <stdio.h>
#include "../core.h"


typedef struct {
    bool enabled;
    bool waitForKeyFrame;
    int64_t nonKeyFrameDropperThreshold,decodedFrameDropperThreshold;
    int skipFrameCount;
    int skippedFrame;
} transcode_dropper_t;


void transcode_dropper_init(transcode_dropper_t* ctx);

bool transcode_dropper_should_drop_frame(transcode_dropper_t *ctx,int64_t lastQueuedDts,AVFrame *frame);
bool transcode_dropper_should_drop_packet(transcode_dropper_t *ctx,int64_t lastQueuedDts,AVPacket *pkt);

#endif /* transcode_dropper_h */
