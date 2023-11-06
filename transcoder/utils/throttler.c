//
//  throttler.c
//  live_transcoder
//
//


#include "../transcode/transcode_session.h"
#include "throttler.h"
#include "json_parser.h"

static void doThrottle(float maxDataRate,
    int coldSeconds,
    int minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate);

int
throttler_init(samples_stats_t *stats,throttler_t *throttler) {
    json_value_t *config = GetConfig();
    json_get_double(config,"throttler.maxDataRate",INFINITY,(double*)&throttler->maxDataRate);
    *(bool*)&throttler->enabled = throttler->maxDataRate < INFINITY;
    if(throttler->enabled){
        json_get_int(config,"throttler.coldSeconds",0,(int*)&throttler->coldSeconds);
        json_get_int(config,"throttler.minThrottleWaitMs",1,(int*)&throttler->minThrottleWaitMs);
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
            const AVRational frameRate = isVideo ? mediaInfo->frameRate :
                (AVRational){ .num = mediaInfo->codecParams->sample_rate ,
                  .den = 1024 };

            doThrottle(throttler->maxDataRate,
                throttler->coldSeconds,
                throttler->minThrottleWaitMs,
                throttler->stats,
                frameRate);
        }
    }
}

static
void
doThrottle(float maxDataRate,
    int coldSeconds,
    int minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate)
{

    if(targetFramerate.den > 0 && targetFramerate.num > 0) {
         float currentDataRate;

         samples_stats_log(CATEGORY_RECEIVER,AV_LOG_DEBUG,stats,"throttleThread-Stats");

         if(stats->totalFrames < coldSeconds * targetFramerate.num / targetFramerate.den) {
             return;
         }

         currentDataRate = stats->currentFrameRate * targetFramerate.den / (float)targetFramerate.num;

         LOGGER(CATEGORY_THROTTLER,
            AV_LOG_DEBUG,"throttleThread. data rate current: %.3f max: %.3f",
            currentDataRate,
            maxDataRate);

         if(currentDataRate > maxDataRate) {
             // going to sleep for a period of time gained due to race
             int throttleWaitUSec = (currentDataRate - maxDataRate) * 1000 * 1000; //av_rescale(1000 * 1000,targetFramerate.den,targetFramerate.num);
             const int minThrottleWaitMs = 1;
             if(throttleWaitUSec > minThrottleWaitMs * 1000) {
                 LOGGER(CATEGORY_THROTTLER,AV_LOG_INFO,"throttleThread. throttling %.3f ms",throttleWaitUSec / 1000.f);
                 stats->throttleWait += av_rescale_q( throttleWaitUSec, clockScale, standard_timebase);
                 av_usleep(throttleWaitUSec);
             }
         }
    }
}