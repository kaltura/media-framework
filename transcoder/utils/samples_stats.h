//
//  Stats.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 17/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef Stats_h
#define Stats_h

#include "core.h"

#define HISTORY_DURATION 10LL //10 seconds
#define HISTORY_SIZE 700LL

typedef struct
{
    uint32_t frameSize;
    uint64_t pts;
    uint64_t clock;
    uint64_t timeStamp;
} samples_stats_history_t ;

typedef struct
{
    uint64_t firstPts;
    uint64_t totalFrames;
    uint64_t head,tail;
    samples_stats_history_t history[HISTORY_SIZE];
    
    int64_t totalWindowSizeInBytes;
    AVRational basetime;
    
    int currentBitRate;
    double currentFrameRate;
    double currentRate;
    int64_t ptsPassed;
    
    uint64_t firstTimeStamp;
    int64_t timeStampPassed;
    int64_t clockDrift;
} samples_stats_t;

void sample_stats_init(samples_stats_t* pStats,AVRational basetime);
void samples_stats_add(samples_stats_t* pStats,uint64_t pts,uint64_t creationTime,int size);
int sample_stats_get_diagnostics(samples_stats_t *pStats,char* buf);
void samples_stats_log(const char* category,int level,samples_stats_t *stats,const char*prefix);

#endif /* Stats_h */
