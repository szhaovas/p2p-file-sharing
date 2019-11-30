//
//  packet.h
//

#ifndef packet_h
#define packet_h

#include "linked-list.h"


#define FILED_NA (-1)
#define MAX_PACKET_LEN 1500

/* Packet Types */
// Exposure intended for peer-proto.c only
#define PTYPE_WHOHAS 0
#define PTYPE_IHAVE  1
#define PTYPE_GET    2
#define PTYPE_DATA   3
#define PTYPE_ACK    4
#define PTYPE_DENIED 5
#define NUM_PACKET_TYPES 6


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

uint8_t* make_empty_packet(void);
LinkedList* make_hash_packets(LinkedList** chunks_ptr);
void print_packet_header(int debug, uint8_t* packet);
void print_hash_payload(int debug, uint8_t* packet);
ssize_t send_packet(int sock, uint8_t* packet, const struct sockaddr_in* addr);


#endif /* packet_h */
