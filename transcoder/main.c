#define __STDC_CONSTANT_MACROS

#include "core.h"
#include <libavutil/timestamp.h>
        
#include <sys/stat.h>
#include <time.h>
#include <stdio.h>
#include <stdbool.h>
#include "logger.h"
#ifndef VERSION
#define VERSION __TIMESTAMP__
#endif

#include "transcode_session.h"
#include "receiver_server.h"
#include "transcode_session_output.h"
#include "json_parser.h"
#include "utils.h"
#include "config.h"
#include <unistd.h>
#include <signal.h>
#include "file_streamer.h"
#include "http_server.h"

#ifndef APPLICATION_VERSION
#define APPLICATION_VERSION __TIMESTAMP__
#endif


transcode_session_t ctx;
receiver_server_t receiver;
receiver_server_t *pDummyPackager=NULL ;
file_streamer_t* file_streamer=NULL;
http_server_t http_server;

int on_http_request(const char* uri, char* buf,int bufSize,int* bytesWritten)
{
    int retVal=404;
    JSON_SERIALIZE_INIT(buf)
    JSON_SERIALIZE_STRING("uri", uri)
    
    char diagnostics[4096];
    strcpy(diagnostics,"{}");
    if (strcmp(uri,"/diagnostics")==0) {
        receiver_server_get_diagnostics(&receiver,diagnostics);
        retVal=200;
    }
    
    JSON_SERIALIZE_OBJECT("result",diagnostics);
    JSON_SERIALIZE_END()
    *bytesWritten=n;
    
    return retVal;
}


int start()
{
    int ret=0;
    int listenPort;
    json_get_int(GetConfig(),"listener.port",9999,&listenPort);
    
    bool useDummyPackager=false;
    json_get_bool(GetConfig(),"debug.dummyPackager",false,&useDummyPackager);
    
    receiver.transcode_session=&ctx;
    receiver.port=9999;
    receiver_server_init(&receiver);
    if (useDummyPackager) {
        pDummyPackager=malloc(sizeof(*pDummyPackager));
        pDummyPackager->port=10000;
        pDummyPackager->transcode_session=NULL;
        receiver_server_init(pDummyPackager);
        receiver_server_async_listen(pDummyPackager);
    }
    
    char file_streamer_input_file[1024];
    strcpy(file_streamer_input_file,"");
    json_get_string(GetConfig(),"input.file","",file_streamer_input_file);
    if (strlen(file_streamer_input_file)>0)
    {
        file_streamer=(file_streamer_t*)av_malloc(sizeof(file_streamer_t));
        file_streamer->source_file_name=file_streamer_input_file;
        
        if ( (ret=file_streamer_start(file_streamer))<0 ) {
            return ret;
        }
    }
    
    //last to start...
    http_server.port=12345;
    http_server.request=on_http_request;
    http_server_start(&http_server);

    receiver_server_sync_listen(&receiver);
    return 0;
}

int stop()
{
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO,"stopping!");
    
    if (file_streamer!=NULL)
    {
        file_streamer_stop(file_streamer);
    }
    receiver_server_close(&receiver);
    return 0;
}

void intHandler(int dummy) {
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_WARNING,"SIGINT detected!");
    stop();
}


void timeout(int ignored)
{
    printf("timed out\n");
    intHandler(0);
}



int main(int argc, char **argv)
{
    log_init(AV_LOG_DEBUG);
    
    LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Version: %s", APPLICATION_VERSION)

    signal(SIGINT, intHandler);
    signal(SIGALRM, timeout);

    int ret=LoadConfig(argc,argv);
    if (ret < 0) {
        return ret;
    }

    //alarm(3);
    
    
    avformat_network_init();
    
    start();
    
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
    
    loggerFlush();
    LOGGER0(CATEGORY_DEFAULT,AV_LOG_INFO,"exiting");

    return 0;
}

