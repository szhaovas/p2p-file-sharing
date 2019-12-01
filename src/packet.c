//
//  packet.c
//

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "debug.h"
#include "packet.h"
#include "sha.h"
#include "chunk.h" // binarytohex()
#include "peer.h"
#include "spiffy.h"


/* Packet Type Strings */
const char* PACKET_TYPE_STRINGS[NUM_PACKET_TYPES] = {
    "WHOHAS",
    "IHAVE",
    "GET",
    "DATA",
    "ACK",
    "DENIED"
};

#define PACKET_TYPE_STRING_MAX_LEN 6
#define FILED_NA (-1)

// Index into |header_field_info| array
#define P_MAGIC 0
#define P_VERSN 1
#define P_PTYPE 2
#define P_HDLEN 3
#define P_PKLEN 4
#define P_SEQNO 5
#define P_ACKNO 6
#define P_NHASH 7

#define HEADER_LEN 16
#define NHASH_WITH_PADDING 4
#define MAX_NUM_HASHES 74
#define MAX_PAYLOAD_LEN (MAX_PACKET_LEN - HEADER_LEN)



/* Table of (offset, size) pairs */
// Keys
#define OFFSET  0
#define SIZE    1
// Size constants
#define SIZE_8  1
#define SIZE_16 2
#define SIZE_32 4
int header_field_info [8][2] = {
    {0, SIZE_16},  // 0. Magic Number          [2 B]
    {2, SIZE_8},   // 1. Version Number        [1 B]
    {3, SIZE_8},   // 2. Packet Type           [1 B]
    {4, SIZE_16},  // 3. Header Length         [2 B]
    {6, SIZE_16},  // 4. Total Packet Length   [2 B]
    {8, SIZE_32},  // 5. Sequence Number       [4 B]
    {12,SIZE_32},  // 6. Acknowledgment Number [4 B]
};


/* Declaring privite setters and getters */
void set_header_len(uint8_t* packet, uint16_t header_len);
void set_packet_len(uint8_t* packet, uint16_t packet_len);
void set_num_hashes(uint8_t* packet, uint8_t num_hashes);
uint16_t get_header_len(uint8_t* packet);
uint16_t get_num_hashes(uint8_t* packet);


/* Setter helper */
void set_field(uint8_t* packet, int field, uint32_t val)
{
    int offset = header_field_info[field][OFFSET];
    int size   = header_field_info[field][SIZE];
    if (size == SIZE_16)
        val = htons(val);
    else if (size == SIZE_32)
        val = htonl(val);
    memcpy(&packet[offset], &val, size);
}

/* Getter helper */
uint32_t get_field(uint8_t* packet, int field)
{
    int offset = header_field_info[field][OFFSET];
    int size   = header_field_info[field][SIZE];
    uint32_t val;
    memcpy(&val, &packet[offset], size);
    if (size == SIZE_16)
       val = ntohs(val);
    else if (size == SIZE_32)
       val = ntohl(val);
    return val;
}



/* Private Setters */
void set_header_len(uint8_t* packet, uint16_t header_len)
{   set_field(packet, P_HDLEN, header_len);    }

void set_packet_len(uint8_t* packet, uint16_t packet_len)
{   set_field(packet, P_PKLEN, packet_len);    }

void set_num_hashes(uint8_t* packet, uint8_t num_hashes)
{   set_field(packet, P_NHASH, num_hashes);    }



/* Public Setters */
void set_magic_number(uint8_t* packet, uint16_t magic_no)
{   set_field(packet, P_MAGIC, magic_no);   }

void set_version(uint8_t* packet, uint8_t version)
{   set_field(packet, P_VERSN, version);   }

void set_packet_type(uint8_t* packet, uint8_t packet_type)
{   set_field(packet, P_PTYPE, packet_type);   }

void set_seq_no(uint8_t* packet, uint32_t seq_no)
{   set_field(packet, P_SEQNO, seq_no);    }

void set_ack_no(uint8_t* packet, uint32_t ack_no)
{   set_field(packet, P_ACKNO, htonl(ack_no));    }

void set_payload(uint8_t* packet, uint8_t* payload, size_t payload_len)
{
    assert(payload_len < MAX_PAYLOAD_LEN);
    memcpy(packet + get_header_len(packet), payload, payload_len);
    set_packet_len(packet, get_header_len(packet) + payload_len);
}



/* Private Getters */
uint16_t get_header_len(uint8_t* packet)
{   return get_field(packet, P_HDLEN);    }

uint16_t get_num_hashes(uint8_t* packet)
{   return get_field(packet, P_NHASH);   }



/* Public Getters */
uint16_t get_magic_no(uint8_t* packet)
{   return get_field(packet, P_MAGIC);   }

uint8_t get_version(uint8_t* packet)
{   return get_field(packet, P_VERSN);   }

uint8_t get_packet_type(uint8_t* packet)
{   return get_field(packet, P_PTYPE);   }

uint16_t get_packet_len(uint8_t* packet)
{   return get_field(packet, P_PKLEN);   }

uint32_t get_seq_no(uint8_t* packet)
{   return get_field(packet, P_SEQNO);   }

uint32_t get_ack_no(uint8_t* packet)
{   return get_field(packet, P_ACKNO);   }

LinkedList* get_hashes(uint8_t* payload)
{
    LinkedList* hashes = new_list();
    uint8_t num_hashes = *payload;
    uint8_t* hash_ptr = payload + NHASH_WITH_PADDING;
    for (uint8_t i = 0; i < num_hashes; i++)
    {
        add_item(hashes, hash_ptr);
        hash_ptr += SHA1_HASH_SIZE;
    }
    return hashes;
}

uint8_t* get_payload(uint8_t* packet)
{   return packet + get_header_len(packet);  }


uint8_t* make_empty_packet()
{
    uint8_t* packet = malloc(MAX_PACKET_LEN);
    memset(packet, '\0', MAX_PACKET_LEN);
    set_header_len(packet, HEADER_LEN);
    return packet;
}



/**
 Make a (new) list of packets with hash payload and a partially filled header.
 */
LinkedList* make_hash_packets(LinkedList** chunks_ptr)
{
    LinkedList* chunks = *chunks_ptr;
    assert(chunks->size > 0);
    LinkedList* recycle = new_list(); // Recycle bin to temporarily hold processed chunks
    LinkedList* packets = new_list();
    int total_hashes = chunks->size;
    int num_packets = (int) ceil( (double) chunks->size / MAX_NUM_HASHES );
    for (int i = 0; i < num_packets; i++)
    {
        // Allocate buffer for this packet
        uint8_t* packet = make_empty_packet();
        
        // Construct hash payload
        uint8_t num_hashes = fmin(chunks->size, MAX_NUM_HASHES);
        uint8_t* payload_start, *payload;
        payload_start = payload = get_payload(packet);
        *payload = num_hashes;
        payload += NHASH_WITH_PADDING;
        for (uint8_t j = 0; j < num_hashes; j++)
        {
            chunk_t* chunk = drop_head(chunks);
            memcpy(payload, chunk->hash, SHA1_HASH_SIZE);
            payload += SHA1_HASH_SIZE;
            add_item(recycle, chunk); // Move the processed hash to recycle bin
        }
        // Construct partial header
        set_packet_len(packet, (uint16_t) (get_header_len(packet) + payload - payload_start));
        add_item(packets, packet);
    }
    assert(chunks->size == 0 && recycle->size == total_hashes);
    delete_empty_list(chunks);
    *chunks_ptr = recycle;
    return packets;
}



size_t print_packet_header_to_str(uint8_t* packet, char* str)
{
    char* str_start = str;
    str += sprintf(str, "------HEADER---------\n");
    str += sprintf(str, "Magic number: %hu\n", get_magic_no(packet));
    str += sprintf(str, "Version:      %d\n", get_version(packet));
    str += sprintf(str, "Type:         %s\n", PACKET_TYPE_STRINGS[get_packet_type(packet)]);
    str += sprintf(str, "Header len:   %hu\n", get_header_len(packet));
    str += sprintf(str, "Packet len:   %hu\n", get_packet_len(packet));
    str += sprintf(str, "------PAYLOAD--------\n");
    return str - str_start;
}



size_t print_hash_payload_to_str(uint8_t* packet, char* str)
{
    char* str_start = str;
    char hash[SHA1_HASH_STR_SIZE+1];
    uint8_t* payload = get_payload(packet);
    uint8_t num_hashes = *payload;
    payload += NHASH_WITH_PADDING;
    str += sprintf(str, "Number of hashes:  %d\n", num_hashes);
    for (uint8_t i = 0; i < num_hashes; i++)
    {
        binary2hex((uint8_t*) payload, SHA1_HASH_SIZE, hash);
        str += sprintf(str, "Hash #%d:  %s\n", i, hash);
        payload += SHA1_HASH_SIZE;
    }
    str += sprintf(str, "======================\n");
    size_t bytes = str - str_start;
    return bytes;
}


void print_packet_header(int debug, uint8_t* packet)
{
    char str[MAX_PACKET_LEN*100];
    print_packet_header_to_str(packet, str);
    DPRINTF(debug, "%s", str);
}
void print_hash_payload(int debug, uint8_t* packet)
{
    char str[MAX_PACKET_LEN*100];
    print_hash_payload_to_str(packet, str);
    DPRINTF(debug, "%s", str);
}


ssize_t send_packet(int sock, uint8_t* packet, const struct sockaddr_in* addr)
{
    return spiffy_sendto(sock,
                         packet,
                         get_packet_len(packet),
                         0,
                         (const struct sockaddr*) addr,
                         sizeof(*addr));
}
