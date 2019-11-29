//
//  peer.h
//

#ifndef peer_h
#define peer_h

#include "bt_parse.h"

typedef struct chunk_s {
    uint16_t id;
    uint8_t hash[SHA1_HASH_SIZE];
} chunk_t;


#endif /* peer_h */
