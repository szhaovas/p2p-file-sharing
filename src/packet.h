//
//  packet.h
//

#ifndef packet_h
#define packet_h

#include "linked-list.h"


#define FILED_NA (-1)
#define MAX_PACKET_LEN 1500

/* Packet Types */
#define PTYPE_WHOHAS 0
#define PTYPE_IHAVE  1
#define PTYPE_GET    2
#define PTYPE_DATA   3
#define PTYPE_ACK    4
#define PTYPE_DENIED 5
#define NUM_PACKET_TYPES 6


void set_magic_number(char* packet, uint16_t magic_no);
void set_version(char* packet, uint8_t version);
void set_packet_type(char* packet, uint8_t packet_type);
void set_seq_no(char* packet, uint32_t seq_no);
void set_ack_no(char* packet, uint32_t ack_no);
void set_payload(char* packet, char* payload, size_t payload_len);

uint16_t get_magic_no(char* packet);
uint8_t  get_version(char* packet);
uint8_t  get_packet_type(char* packet);
uint16_t get_packet_len(char* packet);
uint32_t get_seq_no(char* packet);
uint32_t get_ack_no(char* packet);
LinkedList* get_hashes(char* packet);
char* get_payload(char* packet);

LinkedList* make_hash_packets(LinkedList** hashes_ptr);
size_t print_packet_header_to_str(char* packet, char* str);
size_t print_hash_payload_to_str(char* packet, char* str);


#endif /* packet_h */
