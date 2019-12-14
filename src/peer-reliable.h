//
//  peer-reliable.h
//

#ifndef peer_reliable_h
#define peer_reliable_h

#include <stdint.h>

#define SEC_TO_USEC 1000000
#define WHOHAS_TIMEOUT (10 * SEC_TO_USEC)
#define WHOHAS_RETRY 3
#define RELIABLE_TIMEOUT (3 * SEC_TO_USEC)
#define RELIABLE_RETRY   3



uint64_t get_time(void);
uint64_t get_time_msec(void);


#endif /* peer_reliable_h */
