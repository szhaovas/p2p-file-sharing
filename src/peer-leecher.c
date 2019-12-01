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

LinkedList* _missing_chunks = NULL;
int pending_ihave = 0;
LinkedList* seeder_list = NULL;


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

void handle_IHAVE(PACKET_ARGS)
{
    if (pending_ihave == 0) return;
    
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


void handle_DATA(PACKET_ARGS)
{}



void handle_DENIED(PACKET_ARGS)
{}
