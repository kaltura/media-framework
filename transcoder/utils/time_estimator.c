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

// Original distance-based estimator - kept as fallback
static uint64_t clock_estimator_get_clock_fallback(clock_estimator_t *fifo,int64_t dts)
{
    if (fifo->framesFifoTail==-1) {
        return 0;
    }
    int64_t distance=__INT64_MAX__;
    int64_t clock=0;
    for (int64_t runner=fifo->framesFifoHead;runner>=fifo->framesFifoTail;runner--) {
        clock_estimator_sample_t* sample=&(fifo->samples[runner %  TIME_ESTIMATOR_FIFO_SIZE]);
        int64_t runnerdistance=llabs(dts - sample->dts);
        LOGGER(CATEGORY_CLOCK_ESTIMATOR,AV_LOG_DEBUG,"runnerdistance  %ld distance %ld dts %s cur_dts %s",
            runnerdistance,
            distance,
            pts2str(dts),
            pts2str(sample->dts));
        if (runnerdistance<distance) {
            clock= dts - sample->dts + sample->clock;
            distance=runnerdistance;
            if (distance==0) {
                break;
            }
        }
        // we have a small chance of dts delivered out of order
        // (or too late e.g. after TIME_ESTIMATOR_FIFO_SIZE samples were delivered),
        // so we will continue searching even after we found a closer match
        // this is to prevent wraps / timestamps jumps affecting the clock estimation.
    }
    return clock;
}

uint64_t clock_estimator_get_clock(clock_estimator_t *fifo, const AVPacket *packet)
{
    if (!packet) {
        return 0;
    }

    int64_t dts = packet->dts;
    int64_t created = AV_NOPTS_VALUE;

    // 1. Try to retrieve created timestamp from metadata
    if (get_packet_created_timestamp(packet, &created) == 0) {
        // 2. Use metadata-based stable timing with neighbor estimation by created timestamp

        // Find neighbors in the estimator database for interpolation
        if (fifo->framesFifoTail == -1) {
            // No samples yet, return created timestamp directly
            return created;
        }

        // 3. Look for exact match first, then neighbors in the sample database
        clock_estimator_sample_t *prev_sample = NULL;
        clock_estimator_sample_t *next_sample = NULL;
        clock_estimator_sample_t *sample = NULL;

        for (int64_t runner = fifo->framesFifoHead; runner >= fifo->framesFifoTail; runner--) {
            sample = &(fifo->samples[runner % TIME_ESTIMATOR_FIFO_SIZE]);

            // Look for neighbors by created (clock) values
            if (sample->clock > created) {
                if (!next_sample || sample->clock < next_sample->clock) {
                    next_sample = sample;
                }
            } else {
                // Check for exact DTS match first
                if (sample->dts == dts) {
                    // Exact match found - return the corresponding clock value
                    LOGGER(CATEGORY_CLOCK_ESTIMATOR, AV_LOG_DEBUG,
                        "Exact DTS match: dts=%lld, sample_clock=%lld, created=%lld, using sample_clock",
                        dts, sample->clock, created);
                    return sample->clock;
                }

                prev_sample = sample;
                break;
            }
        }

        // 4. Find the input DTS that corresponds to this created timestamp
        int64_t input_dts = dts; // default fallback

        // 5. Estimate output clock value based on DTS ratio extrapolation
        if (prev_sample && next_sample) {
            // Interpolate to find input_dts based on created timestamp
            int64_t clock_range = next_sample->clock - prev_sample->clock;
            int64_t dts_range = next_sample->dts - prev_sample->dts;

            if (clock_range != 0) {
                input_dts = next_sample->dts -
                    ((next_sample->clock - created) * dts_range) / clock_range;
            } 
        } else if (prev_sample) {
            // Use previous sample as reference for DTS ratio
            input_dts = prev_sample->dts;
        } else if (next_sample) {
            // Use next sample as reference for DTS ratio
            input_dts = next_sample->dts;
        }

        // Apply DTS ratio to created timestamp
        int64_t result = created + (dts - input_dts);

        LOGGER(CATEGORY_CLOCK_ESTIMATOR, AV_LOG_DEBUG,
               "Created-based timing: created=%lld, input_dts=%lld, output_dts=%lld, result=%lld",
               created, input_dts, dts, result);

        return result;
    }

    // 6. Fallback to distance-based estimator when no metadata available
    return clock_estimator_get_clock_fallback(fifo, dts);
}

