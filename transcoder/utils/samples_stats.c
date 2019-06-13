//
//  Stats.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 17/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "samples_stats.h"
#include "logger.h"
#include "utils.h"
#include "json_parser.h"


void sample_stats_init(samples_stats_t* pStats,AVRational basetime)
{
    pStats->totalFrames=0;
    pStats->head=-1;
    pStats->tail=-1;
    pStats->totalWindowSizeInBytes=0;
    pStats->basetime=basetime;
    pStats->currentBitRate=0;
    pStats->currentRate=0;
    pStats->currentFrameRate=0;
    pStats->firstTimeStamp=0;
    pStats->lastTimeStamp=0;
    pStats->lastDts=0;
}

void drain(samples_stats_t* pStats,uint64_t clock)
{
    while (pStats->tail<pStats->head) {
        samples_stats_history_t  *pTail=(samples_stats_history_t*)&pStats->history[ pStats->tail  % HISTORY_SIZE];
        uint64_t timePassed=clock - pTail->dts;
        if (timePassed<HISTORY_DURATION*90000) {
            break;
        }
        pStats->totalWindowSizeInBytes-=pTail->frameSize;
        pStats->tail++;
    }
}

samples_stats_history_t*  sample_stats_get_history(samples_stats_t* pStats,int64_t index) {
    return (samples_stats_history_t*)&(pStats->history[index % HISTORY_SIZE]);
}


void calculate_stats(samples_stats_t* pStats)
{
    if (pStats->head!=-1 && pStats->head!=pStats->tail) {
        samples_stats_history_t  *pHead=sample_stats_get_history(pStats,pStats->head);
        samples_stats_history_t  *pTail=sample_stats_get_history(pStats,pStats->tail);
        
        double clockPassedInSec= (pHead->clock - pTail->clock )  / 1000000.0;
        double dtsPassedInSec= (pHead->dts - pTail->dts )  / 90000.0;
        
        pStats->dtsPassed=(pHead->dts - pStats->firstDts);
        pStats->timeStampPassed=(pHead->timeStamp - pStats->firstTimeStamp);

        int64_t frames=(pStats->head - pStats->tail + 1);
        
        if (dtsPassedInSec>0 && clockPassedInSec>0) {
            double dbitRate= (double)(pStats->totalWindowSizeInBytes*8)/dtsPassedInSec;
            pStats->currentBitRate=(int)dbitRate;
            pStats->currentFrameRate=frames/clockPassedInSec;
            pStats->currentRate=dtsPassedInSec/clockPassedInSec;
            pStats->clockDrift=(pStats->timeStampPassed-pStats->dtsPassed)/90;//to milliseconds
        }
    }
}


void samples_stats_add(samples_stats_t* pStats,uint64_t dts,uint64_t ts,int frameSize)
{
    pStats->head++;
    if (pStats->head==0){
        pStats->tail=0;
        pStats->firstDts=dts;
        pStats->firstTimeStamp=ts;
    }
    samples_stats_history_t  *pHead=sample_stats_get_history(pStats,pStats->head);
    pHead->frameSize=frameSize;
    pStats->lastDts=pHead->dts=dts;
    pHead->clock=getTime64();
    pStats->lastTimeStamp=pHead->timeStamp=ts;
    
    pStats->totalFrames++;
    pStats->totalWindowSizeInBytes+=frameSize;
    
    drain(pStats,pHead->dts);
    calculate_stats(pStats);
}


int sample_stats_get_diagnostics(samples_stats_t *pStats,char* buf)
{
    JSON_SERIALIZE_INIT(buf)
    JSON_SERIALIZE_INT64("totalSamples",pStats->totalFrames)
    JSON_SERIALIZE_INT("bitrate",pStats->currentBitRate)
    JSON_SERIALIZE_DOUBLE("fps",pStats->currentFrameRate)
    JSON_SERIALIZE_DOUBLE("rate",pStats->currentRate)
    JSON_SERIALIZE_INT64("drift",pStats->lastTimeStamp>0 ? pStats->clockDrift : 0);
    JSON_SERIALIZE_STRING("firstTimeStamp",pStats->firstTimeStamp>0 ? ts2str(pStats->firstTimeStamp,false): "N/A")
    JSON_SERIALIZE_STRING("lastTimeStamp",pStats->lastTimeStamp>0 ? ts2str(pStats->lastTimeStamp,false) : "N/A")
    JSON_SERIALIZE_STRING("lastDts",pts2str(pStats->lastDts))
    JSON_SERIALIZE_END()
    return n;
}


void samples_stats_log(const char* category,int level,samples_stats_t *stats,const char *prefix)
{
    LOGGER(category,level,"[%s] Stats: total frames: %ld total time: %s (%s), clock drift %s,bitrate %.2lf Kbit/s fps=%.2lf rate=x%.2lf",
           prefix,
           stats->totalFrames,
           pts2str(stats->dtsPassed),
           pts2str(stats->firstDts),
           pts2str(stats->clockDrift),
           ((double)stats->currentBitRate)/(1000.0),
           stats->currentFrameRate,
           stats->currentRate)
}
