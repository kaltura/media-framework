//
//  time_estimator.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 09/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef time_estimator_h
#define time_estimator_h

#include <stdio.h>
#include "../core.h"

// Forward declaration for AVPacket
struct AVPacket;

#define TIME_ESTIMATOR_FIFO_SIZE 100


typedef struct {
    int64_t dts;
    int64_t clock;
}clock_estimator_sample_t;

typedef struct {
    int64_t framesFifoHead,framesFifoTail;
    clock_estimator_sample_t samples[TIME_ESTIMATOR_FIFO_SIZE];
} clock_estimator_t;


void clock_estimator_init(clock_estimator_t *fifo);
void clock_estimator_push_frame(clock_estimator_t *fifo,int64_t dts,int64_t clock);
uint64_t clock_estimator_get_clock(clock_estimator_t *fifo, const struct AVPacket *packet);


#endif /* time_estimator_h */
