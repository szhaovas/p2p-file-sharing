//
//  peer-leecher.c
//
#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include "bt_parse.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-leecher.h"


/* Struct for each chunk to download */
typedef struct _seeder_t {
    bt_peer_t* peer;
    LinkedList* download_list;
} seeder_t;

typedef struct _download_t {
    int next_packet;
    chunk_t* chunk;
} download_t;


// Chunks that need a seeder
LinkedList* pending_chunks = NULL;
int pending_ihave = 0;
LinkedList* seeder_list = NULL;


/**
 Flood the P2P network with WHOHAS packets containing missing chunk hashes.
 */
void flood_WHOHAS(LinkedList* missing_chunks, bt_peer_t* peers, short id, int sock)
{
    // Record chunks that need a seeder
    pending_chunks = missing_chunks;
    pending_ihave = pending_chunks->size;
    
    // Construct WHOHAS packets
    LinkedList* packets = make_hash_packets(&pending_chunks);
    
    // Send packets to everyone else
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
}


/**
 Handle IHAVE replies.
 */
void handle_IHAVE(PACKET_ARGS)
{
    // Ignore IHAVE reply if none is expected
    if (pending_ihave == 0) return;
    
    LinkedList* hashes = get_hashes(payload);
    if (!seeder_list) seeder_list = new_list();
    // Look for the IHAVE sender in the seeder list
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
    
    // Go through the pending chunks, and see which one(s) this seeder has
    ITER_LOOP(pending_chunks_it, pending_chunks)
    {
        chunk_t* pending_chunk = iter_get_item(pending_chunks_it);
        ITER_LOOP(hashes_it, hashes)
        {
            uint8_t* hash = iter_get_item(hashes_it);
            // This seeder can seed one of the pending chunks
            if (!memcmp(pending_chunk->hash, hash, SHA1_HASH_SIZE))
            {
                // Decide to download this chunk from the seeder
                download_t* download = malloc(sizeof(download_t));
                download->chunk = pending_chunk;
                // Add the download object to the peer's download list
                add_item(seeder->download_list, download);
                // Mark this chunk as no longer pending
                iter_drop_curr(pending_chunks_it);
                pending_ihave -= 1;
                break;
            }
        }
        ITER_END(hashes_it);
    }
    ITER_END(pending_chunks_it);
    
    // Start sending GET to the seeders if all IHAVE replies were received
    if (pending_ihave == 0)
    {
        ITER_LOOP(seeder_it, seeder_list)
        {
            seeder_t* seeder = iter_get_item(seeder_it);
            // Start downloading from the top of the list
            download_t* download = get_head(seeder->download_list);
            download->next_packet = 0;
            // Send GET to this seeder
            uint8_t* packet = make_empty_packet();
            set_packet_type(packet, PTYPE_GET);
            set_payload(packet, download->chunk->hash, SHA1_HASH_SIZE);
            send_packet(sock, packet, &seeder->peer->addr);
        }
        ITER_END(seeder_it);
    }
}


void handle_DATA(PACKET_ARGS)
{}



void handle_DENIED(PACKET_ARGS)
{}
