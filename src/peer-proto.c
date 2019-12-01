//
//  peer-proto.c
//

#include <assert.h>
#include <stdlib.h> // malloc(), free()
#include <string.h> // memcmp()
#include "peer-proto.h"
#include "debug.h"
#include "spiffy.h"
#include "packet.h"


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

/* Struct for each chunk to download */
typedef struct _seeder_t {
    bt_peer_t* peer;
    LinkedList* download_list;
} seeder_t;

typedef struct _download_t {
    int next_packet;
    chunk_t* chunk;
} download_t;

LinkedList* _missing_chunks = NULL;
int pending_ihave = 0;
LinkedList* seeder_list = NULL;

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
void handle_packet(uint8_t* packet, LinkedList* owned_chunks, int sock, bt_peer_t* from)
{
    uint16_t magic_no = get_magic_no(packet);
    uint8_t version = get_version(packet);
    uint8_t packet_type = get_packet_type(packet);
    if (packet_type < NUM_PACKET_TYPES &&
        magic_no == MAGIC_NUMBER && version == VERSION)
    {
        (*handlers[packet_type])(get_seq_no(packet),
                                 get_ack_no(packet),
                                 get_payload(packet),
                                 owned_chunks,
                                 sock,
                                 from);
    }
}




/**
 Flood the network with WHOHAS packets containing missing chunks.
 */
void flood_WHOHAS(LinkedList* missing_chunks, bt_peer_t* peers, short id, int sock)
{
    // Initialize download list and chunks to download
    _missing_chunks = missing_chunks;
    pending_ihave = _missing_chunks->size;
    
    // Construct WHOHAS packets
    LinkedList* packets = make_hash_packets(&_missing_chunks);
    
    ITER_LOOP(packets_it, packets)
    {
        uint8_t* packet = iter_get_item(packets_it);
        // Set fields
        make_generic_header(packet);
        set_packet_type(packet, PTYPE_WHOHAS);
        // Send packet
        for (bt_peer_t* peer = peers; peer != NULL; peer = peer->next)
        {
            if (peer->id == id) continue;
            if (send_packet(sock, packet, &peer->addr) < 0)
            {
                perror("process_get could not send packet");
            }
        }
        free(iter_drop_curr(packets_it));
    }
    ITER_END(packets_it);
    delete_empty_list(packets);
    ITER_LOOP(_missing_chunks_it, _missing_chunks)
    {
        chunk_t* chunk = iter_get_item(_missing_chunks_it);
        DPRINTF(DEBUG_CMD_GET, "Chunk #%d ", chunk->id);
        print_hex(DEBUG_CMD_GET, chunk->hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_CMD_GET, "\n");
    }
}




void handle_WHOHAS(PACKET_ARGS)
{
    LinkedList* hashes = get_hashes(payload);
    // Go through requested hashes and collect hashes this peer owns
    LinkedList* matched_chunks = new_list();
    ITER_LOOP(hashes_it, hashes)
    {
        uint8_t* hash = iter_get_item(hashes_it);
        DPRINTF(DEBUG_IN_WHOHAS, "Looking for ");
        print_hex(DEBUG_IN_WHOHAS, hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_IN_WHOHAS, "\n");
        
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* chunk = iter_get_item(owned_chunks_it);
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
            uint8_t* packet = iter_get_item(packets_it);
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
{
    ITER_LOOP(_missing_chunks_it, _missing_chunks)
    {
        chunk_t* chunk = iter_get_item(_missing_chunks_it);
        DPRINTF(DEBUG_CMD_GET, "Chunk #%d ", chunk->id);
        print_hex(DEBUG_CMD_GET, chunk->hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_CMD_GET, "\n");
    }
    ITER_END(_missing_chunks_it);
    
    LinkedList* hashes = get_hashes(payload);
    if (!seeder_list)
        seeder_list = new_list();
    // Look for the IHAVE sender in the list of seeders
    seeder_t* seeder = NULL;
    ITER_LOOP(seeder_it, seeder_list)
    {
        seeder_t* peer_dl = iter_get_item(seeder_it);
        if (peer_dl->peer == from)
        {
            seeder = peer_dl;
        }
    }
    ITER_END(seeder_it);
    
    // If this is a new seeder, add it to the seeder list
    if (!seeder)
    {
        seeder = malloc(sizeof(seeder_t));
        seeder->peer = from;
        seeder->download_list = new_list();
        add_item(seeder_list, seeder);
    }
    
    // Add the chunks that are still missing to the seeder's download list
    ITER_LOOP(missing_chunks_it, _missing_chunks)
    {
        chunk_t* missing_chunk = iter_get_item(missing_chunks_it);
        ITER_LOOP(hashes_it, hashes)
        {
            uint8_t* hash = iter_get_item(hashes_it);
            // Found a chunk that's still missing
            if (!memcmp(missing_chunk->hash, hash, SHA1_HASH_SIZE))
            {
                // Make a download_t object out of this missing chunk
                download_t* download = malloc(sizeof(download_t));
                download->chunk = missing_chunk;
                download->next_packet = 0;
                // Add the download to the peer's download list
                add_item(seeder->download_list, download);
                iter_drop_curr(missing_chunks_it);
                pending_ihave -= 1;
                break;
            }
        }
        ITER_END(hashes_it);
    }
    ITER_END(missing_chunks_it);
    
    // Start sending GET if all IHAVE replies were received
    if (pending_ihave == 0)
    {
        ITER_LOOP(seeder_it, seeder_list)
        {
            seeder_t* seeder = iter_get_item(seeder_it);
            download_t* download = get_head(seeder->download_list);
            download->next_packet = 0;
            uint8_t* packet = make_empty_packet();
            set_packet_type(packet, PTYPE_GET);
            set_payload(packet, download->chunk->hash, SHA1_HASH_SIZE);
            send_packet(sock, packet, &seeder->peer->addr);
        }
        ITER_END(seeder_it);
    }
}


void handle_GET(PACKET_ARGS)
{}


void handle_DATA(PACKET_ARGS)
{}


void handle_ACK(PACKET_ARGS)
{}


void handle_DENIED(PACKET_ARGS)
{}
