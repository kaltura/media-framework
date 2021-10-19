#include "policy_provider.h"
#include "json_parser.h"
#include "./logger.h"

static
bool isFatalError(int error) {
    switch(error) {
    case AVERROR(ENOMEM):
        return true;
    default:
        return false;
    };
}

static
int errorOnExitHandler(policy_provider_t provider,int error){
    bool exitOnError = *(bool*)&provider->ctx;
    bool isFatal = isFatalError(error);
    bool shouldExit = exitOnError || isFatal;
    int logLevel = shouldExit ? AV_LOG_ERROR : AV_LOG_INFO;
    LOGGER(CATEGORY_TRANSCODING_SESSION,logLevel,"errorOnExitHandler exitOnError: %d is error fatal?: %s",exitOnError,
        isFatal ? "yes" : "no");
    return shouldExit ? error : 0;
}

int init_policy_provider(policy_provider_t provider,json_value_t* config) {
    memset(provider,0,sizeof(*provider));
    json_get_bool(config,"errorPolicy.exitOnError",false,(bool*)&provider->ctx);
    LOGGER(CATEGORY_TRANSCODING_SESSION,AV_LOG_INFO,"init_policy_provider %d",*(bool*)&provider->ctx);
    provider->handle_error = &errorOnExitHandler;
    return 0;
}
void free_policy_provider(policy_provider_t provider){

}