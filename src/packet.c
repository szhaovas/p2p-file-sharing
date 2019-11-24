//
//  packet.c
//  peer
//
//  Created by work on 11/23/19.
//  Copyright © 2019 team1. All rights reserved.
//

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "sha.h"


// (offset, size) pairs
int packet_field_info [8][2] = {
    {0, 2},  // 0. Magic Number          [2 B, uint16_t]
    {2, 1},  // 1. Version Number        [1 B, uint8_t ]
    {3, 1},  // 2. Packet Type           [1 B, uint8_t ]
    {4, 2},  // 3. Header Length         [2 B, uint16_t]
    {6, 2},  // 4. Total Packet Length   [2 B, uint16_t]
    {8, 4},  // 5. Sequence Number       [4 B, uint32_t]
    {12, 4}, // 6. Acknowledgment Number [4 B, uint32_t]
    {16, 1}, // 7. Number of hashes      [1 B, uint8_t ]
};


void make_header(char* buf,
                 uint8_t  packet_type,
                 uint16_t header_len,
                 uint16_t packet_len,
                 uint32_t seq_no,
                 uint32_t ack_no)
{
    MAKE_FIELD(buf, P_MAGIC, htons(MAGIC_NUMBER));
    MAKE_FIELD(buf, P_VERSN, VERSION);
    MAKE_FIELD(buf, P_PTYPE, packet_type);
    MAKE_FIELD(buf, P_HDLEN, htons(header_len));
    MAKE_FIELD(buf, P_PKLEN, htons(packet_len));
    MAKE_FIELD(buf, P_SEQNO, htonl(seq_no));
    MAKE_FIELD(buf, P_ACKNO, htonl(ack_no));
}

void make_payload(char* buf, char* payload, size_t payload_len)
{
    memcpy(buf, payload, payload_len);
}

int make_packet(char* buf,
                uint8_t  packet_type,
                uint16_t header_len,
                uint16_t packet_len,
                uint32_t seq_no,
                uint32_t ack_no,
                char* payload, size_t payload_len)
{
    make_header(buf, packet_type, header_len, packet_len, seq_no, ack_no);
    make_payload(buf + header_len, payload, payload_len);
    return 0;
}



int parse_packet(char* buf,
                 uint8_t*  packet_type,
                 uint16_t* header_len,
                 uint16_t* packet_len,
                 uint32_t* seq_no,
                 uint32_t* ack_no,
                 char** payload)
{
    uint16_t magic_no;
    uint8_t version;
    EXTRACT_FIELD(buf, P_MAGIC, &magic_no);
    EXTRACT_FIELD(buf, P_VERSN, &version);
    EXTRACT_FIELD(buf, P_PTYPE, packet_type);
    EXTRACT_FIELD(buf, P_HDLEN, header_len);
    EXTRACT_FIELD(buf, P_PKLEN, packet_len);
    EXTRACT_FIELD(buf, P_SEQNO, seq_no);
    EXTRACT_FIELD(buf, P_ACKNO, ack_no);
    *payload = buf + HEADER_LEN;
    
    magic_no = ntohs(magic_no);
    *header_len = ntohs(*header_len);
    *packet_len = ntohs(*packet_len);
    *seq_no = ntohl(*seq_no);
    *ack_no = ntohl(*ack_no);
    return magic_no == MAGIC_NUMBER && version == VERSION;
}

}
