//
//  peer-proto.c
//

#include <stdlib.h> // malloc(), free()
#include <string.h> // memcmp()
#include "peer-proto.h"
#include "debug.h"
#include "sha.h"
#include "spiffy.h"
#include "packet.h"
#include "peer.h"


/* Implementation-specific constants */
#define MAGIC_NUMBER 3752
#define VERSION 1

/* Argments to packet handlers */
#define PACKET_ARGS \
    uint32_t seq_no, uint32_t ack_no, char* payload, \
    LinkedList* owned_chunks, struct sockaddr_in* from, socklen_t fromlen, int sock

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
packet_handler_t handlers[NUM_PACKET_TYPES] = {
    handle_WHOHAS,
    handle_IHAVE,
    handle_GET,
    handle_DATA,
    handle_ACK,
    handle_DENIED
};


/**
 Set packet's magic number and version to the implementation-specific numbers.
 */
void make_generic_header(char* packet)
{
    set_magic_number(packet, MAGIC_NUMBER);
    set_version(packet, VERSION);
}


/**
 Dispatch a packet to the appropriate handler.
 */
void handle_packet(char* packet, LinkedList* owned_chunks,
                   struct sockaddr_in* from, socklen_t fromlen, int sock)
{
    uint16_t magic_no = get_magic_no(packet);
    uint8_t version = get_version(packet);
    uint8_t packet_type = get_packet_type(packet);
    if (packet_type < NUM_PACKET_TYPES &&
        magic_no == MAGIC_NUMBER && version == VERSION)
    {
        uint32_t seq_no = get_seq_no(packet);
        uint32_t ack_no = get_ack_no(packet);
        char* payload = get_payload(packet);
        (*handlers[packet_type])(seq_no, ack_no, payload, owned_chunks, from, fromlen, sock);
    }
}



void handle_WHOHAS(PACKET_ARGS)
{
    LinkedList* hashes = get_hashes(payload);
    // Go through requested hashes and collect hashes this peer owns
    LinkedList* matched_hashes = new_list();
    ITER_LOOP(hashes_it, hashes)
    {
        char* hash = (char *) iter_get_item(hashes_it);
        DPRINTF(DEBUG_IN_WHOHAS, "Looking for ");
        print_hex(DEBUG_IN_WHOHAS, hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_IN_WHOHAS, "\n");
        
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* chunk = (chunk_t *) iter_get_item(owned_chunks_it);
            if (!memcmp(hash, chunk->hash, SHA1_HASH_SIZE))
            {
                DPRINTF(DEBUG_IN_WHOHAS, "Found in chunk #%hu\n", chunk->id);
                add_item(matched_hashes, hash);
                iter_drop_curr(hashes_it);
                break;
            }
        }
        ITER_END(owned_chunks_it);
    }
    ITER_END(hashes_it);
    delete_list(hashes);
    
    if (matched_hashes->size)
    {
        LinkedList* packets = make_hash_packets(&matched_hashes);
        bt_peer_t* to_peer = find_peer_with_addr(from);
        if (to_peer)
        {
            ITER_LOOP(packets_it, packets)
            {
                char* packet = (char*) iter_get_item(packets_it);
                make_generic_header(packet);
                set_packet_type(packet, PTYPE_IHAVE);
                char packet_str[MAX_PACKET_LEN*100];
                char* packet_str_ptr = packet_str;
                
                packet_str_ptr += print_packet_header_to_str(packet, packet_str_ptr);
                packet_str_ptr += print_hash_payload_to_str(packet, packet_str_ptr);
                DPRINTF(DEBUG_IN_WHOHAS, "%s", packet_str);
                uint16_t packet_len = get_packet_len(packet);
                sendto(sock, packet, packet_len, 0,
                       (const struct sockaddr *) &(to_peer->addr),
                       sizeof(to_peer->addr));
                free(iter_drop_curr(packets_it));
            }
            ITER_END(packets_it);
        }
        delete_empty_list(packets);
    }
    delete_list(matched_hashes);
}


void handle_IHAVE(PACKET_ARGS)
{}

void handle_GET(PACKET_ARGS)
{}

void handle_DATA(PACKET_ARGS)
{}

void handle_ACK(PACKET_ARGS)
{}

void handle_DENIED(PACKET_ARGS)
{}
