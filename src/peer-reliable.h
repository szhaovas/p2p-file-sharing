//
//  peer-reliable.h
//

#ifndef peer_reliable_h
#define peer_reliable_h

#include <sys/time.h>
#include <stdint.h>


#define SEC_TO_USEC 1000000
#define RELIABLE_TIMEOUT (3 * SEC_TO_USEC)
#define RELIABLE_RETRY   2

uint64_t get_time(void);


#endif /* peer_reliable_h */
