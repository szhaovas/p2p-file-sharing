//
//  peer-reliable.c
//
#include <sys/time.h>
#include "peer-reliable.h"

uint64_t get_time()
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return now.tv_sec * SEC_TO_USEC + now.tv_usec;
}

uint64_t get_time_milli()
{
    return get_time()*USEC_TO_MSEC;
}
