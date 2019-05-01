//
//  httpServer.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 22/03/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "core.h"
#include "http_server.h"
#include "utils.h"
#include "logger.h"
#include <pthread.h>
#include "config.h"


#define CATEGORY_HTTP_SERVER "HttpServer"


static void process_client(AVIOContext *client,http_request_callback callback)
{
    uint8_t buf[10240];
    int ret, n, reply_code;
    uint8_t *resource = NULL;
    while ((ret = avio_handshake(client)) > 0) {
        av_opt_get(client, "resource", AV_OPT_SEARCH_CHILDREN, &resource);
        // check for strlen(resource) is necessary, because av_opt_get()
        // may return empty string.
        if (resource && strlen(resource))
            break;
        
        av_freep(&resource);
    }
    if (ret < 0)
        goto end;
    
    //av_log(client, AV_LOG_TRACE, "resource=%p\n", resource);
    
    if (resource && resource[0] == '/') {
        reply_code =  callback(resource,buf,sizeof(buf),&n);
    } else {
        reply_code = AVERROR_HTTP_NOT_FOUND;
    }
    if ((ret = av_opt_set_int(client, "reply_code", reply_code, AV_OPT_SEARCH_CHILDREN)) < 0) {
        LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_ERROR, "Failed to set reply_code: %d (%s)", av_err2str(ret));
        goto end;
    }
    if ((ret = av_opt_set(client, "content_type", "application/json", AV_OPT_SEARCH_CHILDREN)) < 0) {
        LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_ERROR, "Failed to set content_type: %d (%s)", ret,av_err2str(ret));
        goto end;
    }

    LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_DEBUG,  "Setting reply code to %d", reply_code);
    
    while ((ret = avio_handshake(client)) > 0);
    
    if (ret < 0)
        goto end;
    
    LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_DEBUG, "Handshake performed");
    if (reply_code != 200)
        goto end;
    
    avio_write(client, buf, n);
end:
    LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_DEBUG, "Flushing client");
    avio_flush(client);
    LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_DEBUG, "Closing client");
    avio_close(client);
    av_freep(&resource);
}

void* httpServerThread(void *vargp)
{
    http_server_t* http_server=(http_server_t*)vargp;

    LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_INFO,"http listener thread");

    LOGGER0(CATEGORY_RECEIVER,AV_LOG_INFO,"Waiting for accept");
    
    AVIOContext *client = NULL;
    int ret=0;
    for(;;) {
        if ((ret = avio_accept(http_server->http, &client)) < 0) {
            LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_INFO,"Failed to avio_accept: %d (%s)", ret,av_err2str(ret));
            break;
        }
        LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_INFO,"Accepted client from");
        process_client(client,http_server->request);
    }
    
    LOGGER0(CATEGORY_HTTP_SERVER,AV_LOG_INFO,"Completed receive thread");
    
    return NULL;
}


int http_server_start(http_server_t * http_server)
{
    
    AVDictionary *options = NULL;
    int ret=0;
    
    if ((ret = av_dict_set(&options, "listen", "2", 0)) < 0) {
        LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_FATAL,"http listener failed set listen mode for %d %s",ret,av_err2str(ret));
        return ret;
    }
    if ((ret = avio_open2(&http_server->http, "http://localhost:12345", AVIO_FLAG_WRITE, NULL, &options)) < 0) {
        LOGGER(CATEGORY_HTTP_SERVER,AV_LOG_FATAL,"Failed to open server: %d %s",ret,av_err2str(ret));
        return ret;
    }
    
    pthread_create(&http_server->thread_id, NULL, httpServerThread,http_server);
    return 0;
}


int http_server_stop(http_server_t *http_server) {
    
    pthread_join(http_server->thread_id,NULL);
    return 0;
}

int http_server_close(http_server_t *http_server) {
    
    avio_close(http_server->http);
    return 0;
}
