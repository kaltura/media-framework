

#ifndef core_h
#define core_h

#include "libs.h"

#define _S(EXP) if ((EXP)<0) { return -1;}
#ifndef u_char
#define u_char  unsigned char
#endif

#define MAX_URL_LENGTH 1024
#define MAX_DIAGNOSTICS_STRING_LENGTH 4096

#include "./utils/config.h"
#include "./utils/logger.h"
#include "./utils/utils.h"


#endif
