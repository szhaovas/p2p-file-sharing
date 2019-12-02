//
//  peer.h
//

#ifndef peer_h
#define peer_h

#include "bt_parse.h"
#include "linked-list.h"
#include "sha.h"


/* Implementation-specific constants */
#define MAGIC_NUMBER 3752
#define VERSION 1


/* Chunk struct */
typedef struct _chunk_t {
    uint16_t id;
    uint8_t hash[SHA1_HASH_SIZE];
    char hash_str[SHA1_HASH_STR_SIZE+1];
    char hash_str_short[SHA1_HASH_STR_SIZE+1];
} chunk_t;



/* Packet handlers */

/* Argments for packet handlers */
#define PACKET_ARGS \
    uint32_t seq_no, uint32_t ack_no, uint8_t* payload, uint16_t payload_len, uint8_t* packet, \
    LinkedList* owned_chunks, int sock, bt_peer_t* from, bt_config_t* config

/* Packet handler type */
typedef void (*packet_handler_t)(PACKET_ARGS);

/* Declaring packet handlers */
#define PACKET(handler_name) void handler_name(PACKET_ARGS)
PACKET(handle_WHOHAS);
PACKET(handle_IHAVE);
PACKET(handle_GET);
PACKET(handle_DATA);
PACKET(handle_ACK);
PACKET(handle_DENIED);

/* Table of packet handlers */
extern packet_handler_t handlers[NUM_PACKET_TYPES];



/* Public functions */
void make_generic_header(uint8_t* packet);
void get_short_hash_str(const char* hash_str, char* hash_str_short);
void print_short_hash_str(int level, uint8_t* hash);


#endif /* peer_h */
