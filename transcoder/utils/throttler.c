//
//  throttler.c
//  live_transcoder
//
//


#include "../transcode/transcode_session.h"
#include "throttler.h"
#include "json_parser.h"

// forward declarations
static void doThrottle(float maxDataRate,
    double minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate);

static
bool getFrameRateFromMediaInfo(
    const transcode_mediaInfo_t *mediaInfo,
    AVRational *result);

// api
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
            AVRational frameRate = {0};

            if(!throttler->useStatsDataRate) {
                getFrameRateFromMediaInfo(mediaInfo,&frameRate);
            }

            doThrottle(throttler->maxDataRate,
                throttler->minThrottleWaitMs,
                throttler->stats,
                frameRate);
        }
    }
}

// implementation:
static
bool
getFrameRateFromMediaInfo(
    const transcode_mediaInfo_t *mediaInfo,
    AVRational *result) {
   if(AVMEDIA_TYPE_VIDEO == mediaInfo->codecParams->codec_type){
       *result = mediaInfo->frameRate;
       return true;
   }
   else if(AV_CODEC_ID_AAC == mediaInfo->codecParams->codec_id){
        *result = (AVRational){
            .num = mediaInfo->codecParams->sample_rate ,
            .den = 960 // 1024
        };
        return true;
   }

   LOGGER(CATEGORY_THROTTLER,
       AV_LOG_DEBUG,"%s. unsupported (av) codec %d",
       __FUNCTION__,
       mediaInfo->codecParams->codec_id);

   return false;
}

static
int64_t calculateThrottleWindow(samples_stats_t *stats,AVRational targetFramerate){
     if(targetFramerate.den == 0) {
        if(stats->dtsPassed < 90000) {
            return av_rescale(1000*1000,stats->dtsPassed , 90000);
        }
     } else if(stats->totalFrames * targetFramerate.den < targetFramerate.num) {
         // during startup frame rate is not stable and usually is high
         // due to system delays related to various factors. therefore.
         // we must work with high pressures in small intervals of time.
         // In order to not overshoot we take smaller intervals proportional to
         // time passed since beginning.
         return av_rescale_q(1000*1000,
             (AVRational){stats->totalFrames,1},
             targetFramerate);
      }
      return 1000 * 1000;
}

static
void
doThrottle(float maxDataRate,
    double minThrottleWaitMs,
    samples_stats_t *stats,
    AVRational targetFramerate)
{
     const double currentDataRate = targetFramerate.den == 0 ? stats->currentRate :
        stats->currentFrameRate * targetFramerate.den / (float)targetFramerate.num;

     samples_stats_log(CATEGORY_RECEIVER,AV_LOG_DEBUG,stats,"Throttle-Stats");

     LOGGER(CATEGORY_THROTTLER,
        AV_LOG_DEBUG,"%s. data rate current: %.3f max: %.3f",
        __FUNCTION__,
        currentDataRate,
        maxDataRate);

     if(currentDataRate > maxDataRate) {
         // going to sleep for a period of time gained due to race
         int64_t throttleWindowUs = calculateThrottleWindow(stats,targetFramerate);
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