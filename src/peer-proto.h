//
//  peer-proto.h
//

#ifndef peer_proto_h
#define peer_proto_h

#include <sys/socket.h> // sockaddr_in, socklen_t
#include <netinet/ip.h> // sockaddr_in, socklen_t
#include "linked-list.h"
#include "bt_parse.h"
#include "sha.h"


typedef struct _chunk_t {
    uint16_t id;
    uint8_t hash[SHA1_HASH_SIZE];
} chunk_t;


void handle_packet(uint8_t* packet, LinkedList* owned_chunks,
                   int sock, bt_peer_t* to_peer);

void make_generic_header(uint8_t* packet);

#endif /* peer_proto_h */
