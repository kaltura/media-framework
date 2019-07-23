//
//  time_estimator.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 09/05/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "time_estimator.h"

#define CATEGORY_CLOCK_ESTIMATOR "CLOCKESTIMATOR"

void clock_estimator_init(clock_estimator_t *fifo) {
    fifo->framesFifoHead= fifo->framesFifoTail=-1;
    
}
void clock_estimator_push_frame(clock_estimator_t *fifo,int64_t dts,int64_t clock)
{
    if (fifo->framesFifoTail==-1) {
        fifo->framesFifoTail=fifo->framesFifoHead=0;
    } else {
        fifo->framesFifoHead++;
    }
    if (fifo->framesFifoHead-fifo->framesFifoTail>=TIME_ESTIMATOR_FIFO_SIZE) {
        fifo->framesFifoTail++;
    }
    clock_estimator_sample_t* sample=&(fifo->samples[fifo->framesFifoHead  %  TIME_ESTIMATOR_FIFO_SIZE]);
    sample->clock=clock;
    sample->dts=dts;
}

uint64_t clock_estimator_get_clock(clock_estimator_t *fifo,int64_t dts)
{
    if (fifo->framesFifoTail==-1) {
        return 0;
    }
    int64_t distance=__INT64_MAX__;
    int64_t clock=0;
    for (int64_t runner=fifo->framesFifoHead;runner>=fifo->framesFifoTail;runner--) {
        clock_estimator_sample_t* sample=&(fifo->samples[runner %  TIME_ESTIMATOR_FIFO_SIZE]);
        int64_t runnerdistance=llabs(sample->dts);
        //LOGGER(CATEGORY_CLOCK_ESTIMATOR,AV_LOG_DEBUG,"runnerdistance  %ld distance %ld",runnerdistance,distance);
        if (runnerdistance<distance) {
            clock= dts - sample->dts + sample->clock;
            distance=runnerdistance;
            if (distance==0) {
                break;
            }
        } else {
            break;
        }
    }
    return clock;
}
