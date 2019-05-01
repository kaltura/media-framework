//
//  config.h
//  live_transcoder
//
//  Created by Guy.Jacubovski on 23/02/2019.
//  Copyright © 2019 Kaltura. All rights reserved.
//

#ifndef config_h
#define config_h

#include <stdio.h>
#include "json_parser.h"

int LoadConfig(int argc, char **argv);
json_value_t* GetConfig();

#endif /* config_h */
