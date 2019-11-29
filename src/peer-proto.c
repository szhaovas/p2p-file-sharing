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
    uint32_t seq_no, uint32_t ack_no, uint8_t* payload, \
    LinkedList* owned_chunks, int sock, bt_peer_t* from

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
void make_generic_header(uint8_t* packet)
{
    set_magic_number(packet, MAGIC_NUMBER);
    set_version(packet, VERSION);
}


/**
 Dispatch a packet to the appropriate handler.
 */
void handle_packet(uint8_t* packet, LinkedList* owned_chunks,
                   int sock, bt_peer_t* from)
{
    uint16_t magic_no = get_magic_no(packet);
    uint8_t version = get_version(packet);
    uint8_t packet_type = get_packet_type(packet);
    if (packet_type < NUM_PACKET_TYPES &&
        magic_no == MAGIC_NUMBER && version == VERSION)
    {
        uint32_t seq_no = get_seq_no(packet);
        uint32_t ack_no = get_ack_no(packet);
        uint8_t* payload = get_payload(packet);
        (*handlers[packet_type])(seq_no, ack_no, payload, owned_chunks, sock, from);
    }
}


void handle_WHOHAS(PACKET_ARGS)
{
    LinkedList* hashes = get_hashes(payload);
    // Go through requested hashes and collect hashes this peer owns
    LinkedList* matched_chunks = new_list();
    ITER_LOOP(hashes_it, hashes)
    {
        uint8_t* hash = (uint8_t *) iter_get_item(hashes_it);
        DPRINTF(DEBUG_IN_WHOHAS, "Looking for ");
        print_hex(DEBUG_IN_WHOHAS, hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_IN_WHOHAS, "\n");
        
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* chunk = (chunk_t *) iter_get_item(owned_chunks_it);
            if (!memcmp(hash, chunk->hash, SHA1_HASH_SIZE))
            {
                DPRINTF(DEBUG_IN_WHOHAS, "Found in owned chunk #%hu\n", chunk->id);
                add_item(matched_chunks, chunk);
                // No need to free individual hashes since they were not malloc'ed by get_hashes()
                iter_drop_curr(hashes_it);
                break;
            }
        }
        ITER_END(owned_chunks_it);
    }
    ITER_END(hashes_it);
    delete_list(hashes);
    
    if (matched_chunks->size)
    {
        LinkedList* packets = make_hash_packets(&matched_chunks);
        ITER_LOOP(packets_it, packets)
        {
            uint8_t* packet = (uint8_t*) iter_get_item(packets_it);
            // Set fields
            make_generic_header(packet);
            set_packet_type(packet, PTYPE_IHAVE);
            // Print packet
            print_packet_header(DEBUG_IN_WHOHAS, packet);
            print_hash_payload(DEBUG_IN_WHOHAS, packet);
            // Send packet
            if (send_packet(sock, packet, &from->addr) < 0)
            {
                perror("handle_WHOHAS could not send packet");
            }
            free(iter_drop_curr(packets_it));
        }
        ITER_END(packets_it);
        delete_empty_list(packets);
    }
    // No need to free individual hashes since they were not malloc'ed
    delete_list(matched_chunks);
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
