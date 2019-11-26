//
//  packet.c
//

#include <assert.h>
#include <math.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "packet.h"
#include "sha.h"



// Index into |packet_field_info| array
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
int packet_field_info [8][2] = {
    {0, 2},  // 0. Magic Number          [2 B]
    {2, 1},  // 1. Version Number        [1 B]
    {3, 1},  // 2. Packet Type           [1 B]
    {4, 2},  // 3. Header Length         [2 B]
    {6, 2},  // 4. Total Packet Length   [2 B]
    {8, 4},  // 5. Sequence Number       [4 B]
    {12, 4}, // 6. Acknowledgment Number [4 B]
    {16, 1}, // 7. Number of hashes      [1 B]
};



/* Setter helper */
void set_field(char* packet, int field, uint32_t val)
{
    size_t offset = packet_field_info[field][0];
    size_t size   = packet_field_info[field][1];
    if (size == 2)
        val = htons(val);
    else if (size == 4)
        val = htonl(val);
    memcpy(&packet[offset], &val, size);
}

/* Getter helper */
uint32_t get_field(char* packet, int field)
{
    size_t offset = packet_field_info[field][0];
    size_t size   = packet_field_info[field][1];
    uint32_t val;
    memcpy(&val, &packet[offset], size);
    if (size == 2)
       val = ntohs(val);
    else if (size == 4)
       val = ntohl(val);
    return val;
}



/* Private Setters */
void set_header_len(char* packet, uint16_t header_len)
{   set_field(packet, P_HDLEN, header_len);    }

void set_packet_len(char* packet, uint16_t packet_len)
{   set_field(packet, P_PKLEN, packet_len);    }

void set_num_hashes(char* packet, uint8_t num_hashes)
{   set_field(packet, P_NHASH, num_hashes);    }



/* Public Setters */
void set_magic_number(char* packet, uint16_t magic_no)
{   set_field(packet, P_MAGIC, magic_no);   }

void set_version(char* packet, uint8_t version)
{   set_field(packet, P_VERSN, version);   }

void set_packet_type(char* packet, uint8_t packet_type)
{   set_field(packet, P_PTYPE, packet_type);   }

void set_seq_no(char* packet, uint32_t seq_no)
{   set_field(packet, P_SEQNO, seq_no);    }

void set_ack_no(char* packet, uint32_t ack_no)
{   set_field(packet, P_ACKNO, htonl(ack_no));    }

void set_payload(char* packet, char* payload, size_t payload_len)
{   memcpy(packet + HEADER_LEN, payload, payload_len);  }




/* Private Getters */
uint16_t get_header_len(char* packet)
{   return get_field(packet, P_HDLEN);    }

uint16_t get_num_hashes(char* packet)
{   return get_field(packet, P_NHASH);   }



/* Public Getters */
uint16_t get_magic_no(char* packet)
{   return get_field(packet, P_MAGIC);   }

uint8_t get_version(char* packet)
{   return get_field(packet, P_VERSN);   }

uint8_t get_packet_type(char* packet)
{   return get_field(packet, P_PTYPE);   }

uint16_t get_packet_len(char* packet)
{   return get_field(packet, P_PKLEN);   }

uint32_t get_seq_no(char* packet)
{   return get_field(packet, P_SEQNO);   }

uint32_t get_ack_no(char* packet)
{   return get_field(packet, P_ACKNO);   }

LinkedList* get_hashes(char* packet)
{
    LinkedList* hashes = new_list();
    uint8_t num_hashes = get_num_hashes(packet);
    char* hash_ptr = packet + HEADER_LEN + NHASH_WITH_PADDING;
    for (uint8_t i = 0; i < num_hashes; i++)
    {
        add_item(hashes, hash_ptr);
        hash_ptr += SHA1_HASH_SIZE;
    }
    return hashes;
}

char* get_payload(char* packet)
{   return packet + HEADER_LEN;  }



/**
 Make a (new) list of packets with hash payload and a partially filled header.
 */
LinkedList* make_hash_packets(LinkedList** hashes_ptr)
{
    LinkedList* hashes = *hashes_ptr;
    LinkedList* hashes_recycle = new_list(); // Recycle bin for temporarily holding processed hashes
    LinkedList* packets = new_list();
    int total_hashes = hashes->size;
    int num_packets = (int) ceil( (double) hashes->size / MAX_NUM_HASHES );
    for (int i = 0; i < num_packets; i++)
    {
        // Allocate buffer for this packet
        char* packet = (char* ) malloc(MAX_PACKET_LEN);
        memset(packet, '\0', sizeof(*packet));
        
        // Construct hash payload
        uint8_t num_hashes = fmin(hashes->size, MAX_NUM_HASHES);
        char* payload_start, *payload;
        payload_start = payload = packet + HEADER_LEN;
        *payload = num_hashes;
        payload += NHASH_WITH_PADDING;
        for (uint8_t j = 0; j < num_hashes; j++)
        {
            char* hash = drop_head(hashes);
            memcpy(payload, hash, SHA1_HASH_SIZE);
            payload += SHA1_HASH_SIZE;
            add_item(hashes_recycle, hash); // Move the processed hash to recycle bin
        }
        
        // Construct partial header
        set_header_len(packet, HEADER_LEN);
        set_packet_len(packet, (uint16_t) (HEADER_LEN + payload - payload_start));
        add_item(packets, packet);
    }
    assert(hashes->size == 0 && hashes_recycle->size == total_hashes);
    delete_empty_list(hashes);
    *hashes_ptr = hashes_recycle;
    return packets;
}
