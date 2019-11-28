//
//  peer-proto.h
//

#ifndef peer_proto_h
#define peer_proto_h

#include <sys/socket.h> // sockaddr_in, socklen_t
#include <netinet/ip.h> // sockaddr_in, socklen_t
#include "linked-list.h"

void handle_packet(uint8_t* packet, LinkedList* owned_chunks,
                   struct sockaddr_in* from, socklen_t fromlen, int sock);

void make_generic_header(uint8_t* packet);

#endif /* peer_proto_h */
