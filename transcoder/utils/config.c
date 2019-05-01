//
//  config.c
//  live_transcoder
//
//  Created by Guy.Jacubovski on 23/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#include "config.h"
#include "logger.h"
#include "json_parser.h"
#include <getopt.h>
#include "utils.h"

static struct option long_options[] =
{
    {"configFile", required_argument, NULL, 't'},
    {"config", required_argument, NULL, 'a'},
    {NULL, 0, NULL, 0}
};

static pool_t *pool;
static json_value_t config;

char* configFile=NULL,*configString=NULL;

json_value_t* GetConfig()
{
    return &config;
}

int parseArgs(int argc, char **argv) {
    
    if (argc!=3) {
        printf("syntax: transcoder --configFile [JSONFILE] --config [JSON]\n");
        exit(-1);
    }
    int  ch;
    // loop over all of the options
    while ((ch = getopt_long(argc, argv, "f:c:", long_options, NULL)) != -1)
    {
        // check to see if a single character or long option came through
        switch (ch)
        {
                // short option 't'
            case 'f':
                configFile = optarg; // or copy it if you want to
                break;
                // short option 'a'
            case 'c':
                configString = optarg; // or copy it if you want to
                break;
        }
    }
    return -1;
}
int LoadConfig(int argc, char **argv)
{
    parseArgs(argc,argv);
    
    if (configFile!=NULL) {
        load_file_to_memory(configFile, &configString);
    }
    if (configString==NULL) {
        exit(-1);
    }
    
    char error[128];
    json_status_t status = json_parse(pool, configString, &config, error, sizeof(error));
    if (status!=JSON_OK) {
        LOGGER(CATEGORY_DEFAULT,AV_LOG_FATAL,"Failed parsing configurtion! %s (%s)",configString,error);
        return -1;
    }
    LOGGER(CATEGORY_DEFAULT,AV_LOG_INFO,"Parsed configuration successfully: %s",configString);
    return 0;
}
