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

typedef struct chunk_i {
    short id;
    uint8_t hash[SHA1_HASH_SIZE];
    struct chunk_i* next;
} chunk_info;

bt_peer_t* find_peer_with_addr(struct sockaddr_in* addr);


#endif /* peer_h */
