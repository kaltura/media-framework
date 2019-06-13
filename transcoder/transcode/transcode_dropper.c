//
//  transcode_dropper.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 14/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "transcode_dropper.h"
#include "../utils/logger.h"
#include "../utils/utils.h"
void transcode_dropper_init(transcode_dropper_t* ctx)
{
    ctx->nonKeyFrameDropperThreshold=3*90000LL;
    ctx->decodedFrameDropperThreshold=90000LL;
    ctx->skipFrameCount=0;
    ctx->skippedFrame=0;
    ctx->enabled=false;
}

bool transcode_dropper_should_drop_frame(transcode_dropper_t *ctx,int64_t lastQueuedDts,AVFrame *frame)
{
    //key frames should never be dropped (to keep key frame aligment between all rednitions
    if ((frame->flags & AV_PKT_FLAG_KEY)==AV_PKT_FLAG_KEY) {
        ctx->skippedFrame=0;
        return false;
    }

    int64_t waitTime=lastQueuedDts-frame->pkt_dts;
    if (waitTime>ctx->decodedFrameDropperThreshold && waitTime<ctx->nonKeyFrameDropperThreshold) {
        
        if (ctx->skipFrameCount==0 || ctx->skippedFrame>ctx->skipFrameCount) {
            ctx->skippedFrame=0;
            int delayInSeconds= (int)(waitTime / 90000);
            if (delayInSeconds>1) {
                ctx->skipFrameCount=1;
            }
            if (delayInSeconds>2) {
                ctx->skipFrameCount=2;
            }
            if (delayInSeconds>3) {
                ctx->skipFrameCount=3;
            }
        }
        
        if (ctx->skippedFrame>0) {
            LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"skipping decoded frame  %s  %d / %d (%ld)",getFrameDesc(frame), ctx->skippedFrame,ctx->skipFrameCount,waitTime);
            ctx->skippedFrame++;
            return true;
        }
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"passed decoded frame  %s  %d / %d (%ld)",getFrameDesc(frame), ctx->skippedFrame,ctx->skipFrameCount,waitTime);
        ctx->skippedFrame++;
        return false;
    }
    
    return false;
}

bool transcode_dropper_should_drop_packet(transcode_dropper_t *ctx,int64_t lastQueuedDts,AVPacket *pkt)
{
    int64_t waitTime=lastQueuedDts-pkt->dts;
    if (waitTime>ctx->nonKeyFrameDropperThreshold ) {
        ctx->waitForKeyFrame=true;
        //LOGGER(CATEGORY_DEFAULT,AV_LOG_WARNING,"dropping frame %ld",waitTime);
        //return true;
    }
    
    if (ctx->waitForKeyFrame) {
        if ((pkt->flags & AV_PKT_FLAG_KEY)!=AV_PKT_FLAG_KEY) {
            LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"dropping non-key frame %s  (%ld)",getPacketDesc(pkt), waitTime);
            return true;
        }
        LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"got key frame (%ld)",waitTime);

        ctx->waitForKeyFrame=false;
    }
    
    //LOGGER(CATEGORY_DEFAULT,AV_LOG_WARNING,"[%s] waitTime  %ld",ctx->name,waitTime);
    
    return false;
}
