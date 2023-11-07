//
//  throttler.c
//  live_transcoder
//
//


#include "../transcode/transcode_session.h"
#include "throttler.h"
#include "json_parser.h"

static void doThrottle(float maxDataRate,
    bool useStatsDataRate,
    double minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate);

int
throttler_init(samples_stats_t *stats,throttler_t *throttler) {
    json_value_t *config = GetConfig();
    json_get_double(config,"throttler.maxDataRate",INFINITY,(double*)&throttler->maxDataRate);
    if(throttler->maxDataRate < INFINITY){
        json_get_bool(config,"throttler.useStatsDataRate",false,(bool*)&throttler->useStatsDataRate);
        json_get_double(config,"throttler.minThrottleWaitMs",1,(double*)&throttler->minThrottleWaitMs);
        throttler->stats = stats;
    }
    return 0;
}

void
throttler_process(throttler_t *throttler,transcode_session_t *transcode_session) {
   if(throttler && throttler->maxDataRate < INFINITY) {
        const transcode_mediaInfo_t *mediaInfo = transcode_session ? transcode_session->currentMediaInfo : NULL;
        if(mediaInfo && mediaInfo->codecParams){
            const bool isVideo = mediaInfo->codecParams->codec_type == AVMEDIA_TYPE_VIDEO;
            // TODO: currently only AAC 'fps' is supported, MP3 and opus etc.
            // may have a different frame allocation schemes
            const AVRational frameRate = isVideo ? mediaInfo->frameRate :
                (AVRational){ .num = mediaInfo->codecParams->sample_rate ,
                  .den = 1024 };

            doThrottle(throttler->maxDataRate,
                throttler->useStatsDataRate,
                throttler->minThrottleWaitMs,
                throttler->stats,
                frameRate);
        }
    }
}

static
void
doThrottle(float maxDataRate,
    bool useStatsDataRate,
    double minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate)
{

    if(targetFramerate.den > 0 && targetFramerate.num > 0) {
         const double currentDataRate = useStatsDataRate ? stats->currentRate :
            stats->currentFrameRate * targetFramerate.den / (float)targetFramerate.num;

         samples_stats_log(CATEGORY_RECEIVER,AV_LOG_DEBUG,stats,"Throttle-Stats");

         LOGGER(CATEGORY_THROTTLER,
            AV_LOG_DEBUG,"%s. data rate current: %.3f max: %.3f",
            __FUNCTION__,
            currentDataRate,
            maxDataRate);

         if(currentDataRate > maxDataRate) {
             // going to sleep for a period of time gained due to race
              int throttleWindowUs;
              if(stats->totalFrames * targetFramerate.den < targetFramerate.num) {
                 // during startup frame rate is not stable and usually is high
                 // due to system delays related to various factors. therefore.
                 // we must work with high pressures in small intervals of time.
                 // In order to not overshoot we take smaller intervals proportional to
                 // time passed since beginning.
                 throttleWindowUs = av_rescale_q(1000*1000,
                     (AVRational){stats->totalFrames,1},
                     targetFramerate);
              } else {
                 throttleWindowUs = 1000 * 1000;
              }
             int throttleWaitUSec = (currentDataRate - maxDataRate) * throttleWindowUs;
             if(throttleWaitUSec > minThrottleWaitMs * 1000) {
                 LOGGER(CATEGORY_THROTTLER,AV_LOG_INFO,"%s. throttling %.3f ms",
                 __FUNCTION__,
                 throttleWaitUSec / 1000.f);
                 stats->throttleWait += av_rescale_q(throttleWaitUSec, clockScale, standard_timebase);
                 av_usleep(throttleWaitUSec);
             }
         }
    }
}