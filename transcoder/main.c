#define __STDC_CONSTANT_MACROS

#include "core.h"
#include <libavutil/timestamp.h>

#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/resource.h>

#ifndef VERSION
#define VERSION __TIME__
#endif

#include "transcode_session.h"
#include "receiver_server.h"
#include "transcode_session_output.h"
#include "json_parser.h"
#include <unistd.h>
#include <signal.h>
#include "debug/file_streamer.h"
#include "debug/kmp_streamer.h"
#include "http_server.h"

#ifndef APPLICATION_VERSION
#define APPLICATION_VERSION __TIMESTAMP__
#endif


transcode_session_t ctx;
receiver_server_t receiver;
receiver_server_t *pDummyPackager=NULL ;
file_streamer_t* file_streamer=NULL;
kmp_streamer_t* kmp_streamer=NULL;
http_server_t http_server;

int on_http_request(const char* uri, char* buf,int bufSize,int* bytesWritten)
{
    int retVal=404;
    JSON_SERIALIZE_INIT(buf,bufSize)
        JSON_SERIALIZE_STRING("uri", uri)
        JSON_SERIALIZE_OBJECT_BEGIN("result")
            if (strcmp(uri,"/control/diagnostics")==0) {
                receiver_server_get_diagnostics(&receiver,js);
                retVal=200;
            }
            if (strcmp(uri,"/status")==0) {
                JSON_SERIALIZE_STRING("state", "ready")
                retVal=200;
            }
            if (strcmp(uri,"/control/status")==0) {
                JSON_SERIALIZE_STRING("state", "ready")
                retVal=200;
            }
        JSON_SERIALIZE_OBJECT_END();
    JSON_SERIALIZE_END()
    *bytesWritten=JSON_WRITTEN();

    return retVal;
}


int openDebugStreamers()
{
    int ret=0;
    char file_streamer_input_file[MAX_URL_LENGTH] ={0};
    json_get_string(GetConfig(),"input.file","",file_streamer_input_file,sizeof(file_streamer_input_file));
    if(strlen(file_streamer_input_file) > 4 && !strcmp(file_streamer_input_file + strlen(file_streamer_input_file) - 4, ".kmp"))
    {
        kmp_streamer=(kmp_streamer_t*)av_malloc(sizeof(kmp_streamer_t));
        strcpy(kmp_streamer->source_file_name,file_streamer_input_file);
        sprintf(kmp_streamer->kmp_url,"kmp://localhost:%d",receiver.kmpServer.listenPort);

        if ( (ret=kmp_streamer_start(kmp_streamer))<0 ) {
            return ret;
        }
        return 0;
    }
    if (strlen(file_streamer_input_file)>0)
    {
        file_streamer=(file_streamer_t*)av_malloc(sizeof(file_streamer_t));
        strcpy(file_streamer->source_file_name,file_streamer_input_file);
        sprintf(file_streamer->kmp_url,"kmp://localhost:%d",receiver.kmpServer.listenPort);

        if ( (ret=file_streamer_start(file_streamer))<0 ) {
            return ret;
        }
    }
    return 0;

}

int start()
{
    int ret=0;
    int listenPort;
    json_get_int(GetConfig(),"kmp.listenPort",9000,&listenPort);

    bool useDummyPackager=false;
    json_get_bool(GetConfig(),"debug.dummyPackager",false,&useDummyPackager);

    receiver.transcode_session=&ctx;
    receiver.port=listenPort;
    json_get_string(GetConfig(),"kmp.listenAddress","127.0.0.1",receiver.listenAddress,sizeof(receiver.listenAddress));
    if (receiver_server_init(&receiver)<0) {
        return -1;
    }
    if (useDummyPackager) {
        pDummyPackager=malloc(sizeof(*pDummyPackager));
        pDummyPackager->port=10000;
        pDummyPackager->transcode_session=NULL;
        receiver_server_init(pDummyPackager);
        receiver_server_async_listen(pDummyPackager);
    }

    if ((ret=openDebugStreamers())<0){
        return ret;
    }

    //last to start...
    json_get_int(GetConfig(),"control.listenPort",12345,&listenPort);
    json_get_string(GetConfig(),"control.listenAddress","0.0.0.0",http_server.listenAddress,sizeof(receiver.listenAddress));
    http_server.port=listenPort;
    http_server.request=on_http_request;
    http_server_start(&http_server);

    return receiver_server_sync_listen(&receiver);
}

int stop()
{
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO,"stopping!");

    if (file_streamer!=NULL)
    {
        file_streamer_stop(file_streamer);
    }
    if (kmp_streamer!=NULL){
        kmp_streamer_stop(kmp_streamer);
    }
    receiver_server_close(&receiver);
    loggerFlush();
    return 0;
}

void intHandler(int dummy) {
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_WARNING,"SIGINT detected!");
    stop();
}

void pipeHandler(int dummy) {
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_WARNING,"SIGPIPE detected!");
    stop();
}


int set_resource_limits()
{
    const struct rlimit lim = { .rlim_cur = RLIM_INFINITY, .rlim_max = RLIM_INFINITY};
    int result = setrlimit(RLIMIT_CORE,&lim);
    if( result < 0)
    {
        printf(stderr,"failed to setrlimit(RLIMIT_CORE) with error %d",result);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    if( set_resource_limits() < 0)
    {
        return -1;
    }

    log_init(AV_LOG_DEBUG);

    LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Version: %s", APPLICATION_VERSION)

    signal(SIGINT, intHandler);
    signal(SIGPIPE, pipeHandler);

    int ret=LoadConfig(argc,argv);
    if (ret < 0) {
        return ret;
    }

    char logLevel[10];
    if (JSON_OK==json_get_string(GetConfig(),"logger.logLevel","VERBOSE",logLevel,sizeof(logLevel))) {
        set_log_level(logLevel);
    }

    avformat_network_init();

    if (start() < 0) {
        return -1;
    }

    stop();

    if (file_streamer!=NULL)
    {
        file_streamer_close(file_streamer);
        av_free(file_streamer);
        file_streamer=NULL;
    }

    //http_server_stop(&http_server);
    //http_server_close(&http_server);

    if (pDummyPackager!=NULL) {
        receiver_server_close(pDummyPackager);
    }

    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO,"exiting");
    loggerFlush();

    return 0;
}

