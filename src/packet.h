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

void handle_packet(uint8_t* packet, LinkedList* owned_chunks, int sock, bt_peer_t* from, bt_config_t* config);


void set_magic_number(uint8_t* packet, uint16_t magic_no);
void set_version(uint8_t* packet, uint8_t version);
void set_packet_type(uint8_t* packet, uint8_t packet_type);
void set_seq_no(uint8_t* packet, uint32_t seq_no);
void set_ack_no(uint8_t* packet, uint32_t ack_no);
void set_payload(uint8_t* packet, uint8_t* payload, size_t payload_len);

uint16_t get_magic_no(uint8_t* packet);
uint8_t  get_version(uint8_t* packet);
uint8_t  get_packet_type(uint8_t* packet);
uint16_t get_packet_len(uint8_t* packet);
uint32_t get_seq_no(uint8_t* packet);
uint32_t get_ack_no(uint8_t* packet);
LinkedList* get_hashes(uint8_t* packet);
uint8_t* get_payload(uint8_t* packet);
uint16_t get_payload_len(uint8_t* packet);

int validate_packet(uint8_t* packet, uint16_t magic_no, uint8_t version);
uint8_t* make_empty_packet(void);
LinkedList* make_hash_packets(LinkedList** chunks_ptr);
void print_packet_header(int debug, uint8_t* packet);
void print_hash_payload(int debug, uint8_t* packet);
ssize_t send_packet(int sock, uint8_t* packet, const struct sockaddr_in* addr);


#endif /* packet_h */
