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


/* Table of packet handlers */

packet_handler_t handlers[NUM_PACKET_TYPES] = {
    handle_WHOHAS,
    handle_IHAVE,
    handle_GET,
    handle_DATA,
    handle_ACK,
    handle_DENIED
};


/* Declaring private functions */
void set_header_len(uint8_t* packet, uint16_t header_len);
void set_packet_len(uint8_t* packet, uint16_t packet_len);
void set_num_hashes(uint8_t* packet, uint8_t num_hashes);
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
uint8_t* get_payload(uint8_t* packet);
uint16_t get_payload_len(uint8_t* packet);
uint16_t get_header_len(uint8_t* packet);
uint16_t get_num_hashes(uint8_t* packet);

LinkedList* make_hash_packets(LinkedList** chunks_ptr);
ssize_t send_packet(int sock, uint8_t* packet, const struct sockaddr_in* addr);


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

/* Setters */
void set_header_len(uint8_t* packet, uint16_t header_len)
{   set_field(packet, P_HDLEN, header_len);    }

void set_packet_len(uint8_t* packet, uint16_t packet_len)
{   set_field(packet, P_PKLEN, packet_len);    }

void set_num_hashes(uint8_t* packet, uint8_t num_hashes)
{   set_field(packet, P_NHASH, num_hashes);    }

void set_magic_number(uint8_t* packet, uint16_t magic_no)
{   set_field(packet, P_MAGIC, magic_no);   }

void set_version(uint8_t* packet, uint8_t version)
{   set_field(packet, P_VERSN, version);   }

void set_packet_type(uint8_t* packet, uint8_t packet_type)
{   set_field(packet, P_PTYPE, packet_type);   }

void set_seq_no(uint8_t* packet, uint32_t seq_no)
{   set_field(packet, P_SEQNO, seq_no);    }

void set_ack_no(uint8_t* packet, uint32_t ack_no)
{   set_field(packet, P_ACKNO, ack_no);    }

void set_payload(uint8_t* packet, uint8_t* payload, size_t payload_len)
{
    assert(payload_len <= MAX_PAYLOAD_LEN);
    memcpy(packet + get_header_len(packet), payload, payload_len);
    set_packet_len(packet, get_header_len(packet) + payload_len);
}

/* Getters */
uint16_t get_header_len(uint8_t* packet)
{   return get_field(packet, P_HDLEN);    } // FIXME: cannot trust incoming packets!

uint16_t get_num_hashes(uint8_t* packet)
{   return get_field(packet, P_NHASH);   }

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

uint8_t* get_payload(uint8_t* packet)
{   return packet + get_header_len(packet);  }

uint16_t get_payload_len(uint8_t* packet)
{   return get_packet_len(packet) - get_header_len(packet);   }

ssize_t send_packet(int sock, uint8_t* packet, const struct sockaddr_in* addr)
{
    return spiffy_sendto(sock,
                         packet,
                         get_packet_len(packet),
                         0,
                         (const struct sockaddr*) addr,
                         sizeof(*addr));
}



/* Public functions */

/**
 Make a new list that contains the hashes in the payload.
 */
LinkedList* get_hashes(uint8_t* payload)
{
    LinkedList* hashes = new_list();
    uint8_t num_hashes = *payload;
    uint8_t* hash_ptr = payload + NHASH_WITH_PADDING;
    for (uint8_t i = 0; i < num_hashes; i++)
    {
        insert_tail(hashes, hash_ptr);
        hash_ptr += SHA1_HASH_SIZE;
    }
    return hashes;
}


/**
 Make a packet with generic header.
 */
uint8_t* make_generic_packet()
{
    uint8_t* packet = malloc(MAX_PACKET_LEN);
    memset(packet, '\0', MAX_PACKET_LEN);
    set_magic_number(packet, MAGIC_NUMBER);
    set_version(packet, VERSION);
    set_header_len(packet, HEADER_LEN);
    set_packet_len(packet, HEADER_LEN);
    return packet;
}


/**
 Validate packet by checking various fields.
 */
int validate_packet(uint8_t* packet)
{
    return get_magic_no(packet) == MAGIC_NUMBER &&
           get_version(packet) == VERSION &&
           get_packet_type(packet) < NUM_PACKET_TYPES &&
           get_header_len(packet) == HEADER_LEN &&
           get_packet_len(packet) <= MAX_PACKET_LEN &&
           get_payload_len(packet) <= MAX_PAYLOAD_LEN;
}


/**
 Dispatch a packet to the appropriate handler.
 */
void handle_packet(uint8_t* packet, LinkedList* owned_chunks, bt_peer_t* from, bt_config_t* config)
{
    if (validate_packet(packet))
    {
//        printf("New packet:\n");
//        print_packet_header(DEBUG_NONE, packet);
//        printf("\n");
        uint8_t packet_type = get_packet_type(packet);
        (*handlers[packet_type])(get_seq_no(packet),
                                 get_ack_no(packet),
                                 get_payload(packet),
                                 get_payload_len(packet),
                                 packet,
                                 owned_chunks,
                                 from,
                                 config);
    }
}


void send_get(uint8_t* hash, bt_peer_t* dst, int sock)
{
    uint8_t* packet = make_generic_packet();
    set_packet_type(packet, PTYPE_GET);
    set_payload(packet,hash, SHA1_HASH_SIZE);
    send_packet(sock, packet, &dst->addr);
    free(packet);
}

void send_ack(uint32_t ack_no, bt_peer_t* dst, int sock)
{
    uint8_t* packet = make_generic_packet();
    set_packet_type(packet, PTYPE_ACK);
    set_ack_no(packet, ack_no);
    send_packet(sock, packet, &dst->addr);
    free(packet);
}

void send_whohas(LinkedList** chunks_ptr, bt_peer_t* peers, short me, int sock)
{
    // Construct WHOHAS packets
    LinkedList* packets = make_hash_packets(chunks_ptr);
    
    // Send packets to everyone else
    ITER_LOOP(packets_it, packets)
    {
        uint8_t* packet = iter_get_item(packets_it);
        // Set fields
        set_packet_type(packet, PTYPE_WHOHAS);
        // Send packet
        for (bt_peer_t* peer = peers; peer != NULL; peer = peer->next)
        {
            if (peer->id == me) continue;
            send_packet(sock, packet, &peer->addr);
        }
        free(iter_drop_curr(packets_it));
    }
    ITER_END(packets_it);
    delete_empty_list(packets);
}

void send_ihave(LinkedList** chunks_ptr, bt_peer_t* dst, int sock)
{
    // Construct IHAVE packets
    LinkedList* packets = make_hash_packets(chunks_ptr);
    ITER_LOOP(packets_it, packets)
    {
        uint8_t* packet = iter_get_item(packets_it);
        // Set fields

        set_packet_type(packet, PTYPE_IHAVE);
        // Print packet
        DPRINTF(DEBUG_SEEDER, "Sending IHAVE to peer %d\n", dst->id);
        print_hash_payload(DEBUG_SEEDER, packet);
        // Send packet
        if (send_packet(sock, packet, &dst->addr) < 0)
        {
            perror("Could not send WHOHAS packet");
        }
        free(iter_drop_curr(packets_it));
    }
    ITER_END(packets_it);
    delete_empty_list(packets);
}

void send_data(uint32_t seq_no, uint8_t* data, size_t data_len, bt_peer_t* dst, int sock)
{
    uint8_t* packet = make_generic_packet();
    set_packet_type(packet, PTYPE_DATA);
    set_payload(packet, data, data_len);
    set_seq_no(packet, seq_no);
    send_packet(sock, packet, &dst->addr);
    free(packet);
}


/**
 Make a list of packets with hash payload and a partially filled header.
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
        uint8_t* packet = make_generic_packet();
        
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
            insert_tail(recycle, chunk); // Move processed hash to recycle bin
        }
        // Construct partial header
        set_packet_len(packet, (uint16_t) (get_header_len(packet) + payload - payload_start));
        insert_tail(packets, packet);
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
    if (get_packet_type(packet) == PTYPE_ACK)
    {
    str += sprintf(str, "ACK NO:       %d\n", get_ack_no(packet));
    }
    else if (get_packet_type(packet) == PTYPE_DATA)
    {
    str += sprintf(str, "SEQ NO:       %d\n", get_seq_no(packet));
    }
    str += sprintf(str, "------PAYLOAD--------\n");
    return str - str_start;
}



size_t print_hash_payload_to_str(uint8_t* packet, char* str)
{
    char* str_start = str;
    char hash_str[SHA1_HASH_STR_SIZE+1];
    char hash_str_short[SHA1_HASH_STR_SIZE+1];
    uint8_t* payload = get_payload(packet);
    uint8_t num_hashes = *payload;
    payload += NHASH_WITH_PADDING;
    str += sprintf(str, "Number of hashes:  %d\n", num_hashes);
    for (uint8_t i = 0; i < num_hashes; i++)
    {
        memset(hash_str, '\0', SHA1_HASH_STR_SIZE+1);
        memset(hash_str_short, '\0', SHA1_HASH_STR_SIZE+1);
        binary2hex((uint8_t*) payload, SHA1_HASH_SIZE, hash_str);
        get_short_hash_str(hash_str, hash_str_short);
        str += sprintf(str, "Hash #%d:  %s\n", i, hash_str_short);
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
