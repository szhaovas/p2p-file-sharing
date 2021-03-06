//
//  peer-leecher.h
//

#ifndef peer_leecher_h
#define peer_leecher_h

#include "peer-reliable.h"


int  ongoing_jobs_exist(void);
void get_chunks(LinkedList* missing_chunks, bt_config_t* config);
void leecher_timeout(bt_config_t* config);

#endif /* peer_leecher_h */
