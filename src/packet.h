//
//  packet.h
//  peer
//
//  Created by work on 11/23/19.
//  Copyright © 2019 team1. All rights reserved.
//

#ifndef packet_h
#define packet_h

// Index into |packet_field_info| array
#define P_MAGIC 0
#define P_VERSN 1
#define P_PTYPE 2
#define P_HDLEN 3
#define P_PKLEN 4
#define P_SEQNO 5
#define P_ACKNO 6


#define PTYPE_WHOHAS 0
#define PTYPE_IHAVE  1
#define PTYPE_GET    2
#define PTYPE_DATA   3
#define PTYPE_ACK    4
#define PTYPE_DENIED 5


#define MAGIC_NUMBER 3752
#define VERSION 1
#define HEAD_LEN_NORMAL 16
#define FILED_N_A 0


int make_packet(char* buf,
                uint8_t packet_type,
                uint16_t  header_len,
                uint16_t  packet_len,
                uint32_t seq_no,
                uint32_t ack_no,
                char* payload,
                size_t payload_len);



int parse_packet(char* buf,
                 uint16_t* magic_no,
                 uint8_t*  version,
                 uint8_t* packet_type,
                 uint16_t* header_len,
                 uint16_t* packet_len,
                 uint32_t* seq_no,
                 uint32_t* ack_no,
                 char** payload);



#define MAKE_FIELD(buf, field_name, field_val) \
    do { \
        int val = field_val; \
        memcpy(&buf[packet_field_info[field_name][1]], \
               &val, \
               packet_field_info[field_name][0]);\
    } while (0)

#define EXTRACT_FIELD(buf, field_name, field_ptr) \
    do { \
        memcpy(field_ptr, \
               &buf[packet_field_info[field_name][1]], \
               packet_field_info[field_name][0]);\
    } while (0)


#endif /* packet_h */
