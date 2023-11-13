//  live_transcoder
//

#ifndef Throttler_h
#define Throttler_h

typedef struct {
    const bool useStatsDataRate;
    const double maxDataRate;
    const double minThrottleWaitMs;
    samples_stats_t *stats;
} throttler_t;

int throttler_init(samples_stats_t *stats,throttler_t *throttler);

void
throttler_process(throttler_t *throttler,transcode_session_t *session);

#endif