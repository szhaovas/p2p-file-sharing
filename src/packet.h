//
//  packet.h
//

#ifndef packet_h
#define packet_h

#include "linked-list.h"
#include "bt_parse.h"


#define MAGIC_NUMBER 3752
#define VERSION 1
#define MAX_PACKET_LEN 1500
#define HEADER_LEN 16
#define MAX_PAYLOAD_LEN (MAX_PACKET_LEN - HEADER_LEN)
#define NHASH_WITH_PADDING 4
#define MAX_NUM_HASHES 74

/* Packet Types */
#define PTYPE_WHOHAS 0
#define PTYPE_IHAVE  1
#define PTYPE_GET    2
#define PTYPE_DATA   3
#define PTYPE_ACK    4
#define PTYPE_DENIED 5
#define NUM_PACKET_TYPES 6


/* Packet handlers */
/* Argments for packet handlers */
#define PACKET_ARGS \
    uint32_t seq_no, uint32_t ack_no, uint8_t* payload, uint16_t payload_len, uint8_t* packet, \
    LinkedList* owned_chunks, bt_peer_t* from, bt_config_t* config

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

void handle_packet(uint8_t* packet, LinkedList* owned_chunks, bt_peer_t* from, bt_config_t* config);


LinkedList* get_hashes(uint8_t* packet);
void print_packet_header(int debug, uint8_t* packet);
void print_hash_payload(int debug, uint8_t* packet);

void send_get(uint8_t* hash, bt_peer_t* dst, int sock);
void send_ack(uint32_t ack_no, bt_peer_t* dst, int sock);
void send_whohas(LinkedList** chunks, bt_peer_t* peers, short me, int sock);
void send_ihave(LinkedList** chunks_ptr, bt_peer_t* dst, int sock);
void send_data(uint32_t seq_no, uint8_t* data, size_t data_len, bt_peer_t* dst, int sock);



#endif /* packet_h */
