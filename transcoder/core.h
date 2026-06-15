

#ifndef core_h
#define core_h

#include "libs.h"

#define _S(EXP) {           \
    int retVal = (EXP);     \
    if(retVal < 0) {        \
        return retVal;      \
    }                       \
}

#ifndef u_char
#define u_char  unsigned char
#endif

#define MAX_URL_LENGTH 1024
#define MAX_DIAGNOSTICS_STRING_LENGTH 4096
#include "./utils/config.h"
#include "./utils/logger.h"
#include "./utils/utils.h"


#endif
