//
//  peer-leecher.c
//
#include <math.h>
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
    uint32_t next_packet;
    uint64_t remaining_bytes;
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


void send_get_packet(download_t* dl, seeder_t* seeder, int sock)
{
    dl->next_packet = 0;
    dl->remaining_bytes = CHUNK_SIZE;
    uint8_t* packet = make_empty_packet();
    make_generic_header(packet);
    set_packet_type(packet, PTYPE_GET);
    set_payload(packet, dl->chunk->hash, SHA1_HASH_SIZE);
    send_packet(sock, packet, &seeder->peer->addr);
    DPRINTF(DEBUG_LEECHER, "GET chunk %i (%s) from seeder %d\n",
            dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
    print_packet_header(DEBUG_LEECHER, packet);
    free(packet);
}


/**
 Handle IHAVE replies.
 */
void handle_IHAVE(PACKET_ARGS)
{
    // Ignore IHAVE reply if none is expected
    if (pending_ihave == 0)
    {
        DPRINTF(DEBUG_LEECHER, "Ignore unexpected IHAVE packet\n");
        return;
    }
    
    LinkedList* hashes = get_hashes(payload);
    if (!seeder_list) seeder_list = new_list();
    // Look for the IHAVE sender in the seeder list
    seeder_t* seeder = NULL;
    ITER_LOOP(seeder_it, seeder_list)
    {
        seeder_t* peer_dl = iter_get_item(seeder_it);
        if (peer_dl->peer->id == from->id)
            seeder = peer_dl;
    }
    ITER_END(seeder_it);
    
    // If this is a new seeder, add it to the seeder list
    if (!seeder)
    {
        seeder = malloc(sizeof(seeder_t));
        seeder->peer = from;
        seeder->download_list = new_list();
        insert_tail(seeder_list, seeder);
        DPRINTF(DEBUG_LEECHER, "Found a new seeder (#%d)\n", seeder->peer->id);
    }
    DPRINTF(DEBUG_LEECHER, "Available data hashes from seeder %d\n", seeder->peer->id);
    print_hash_payload(DEBUG_LEECHER, packet);
    
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
                insert_tail(seeder->download_list, dl);
                // Mark this chunk as no longer pending
                iter_drop_curr(pending_chunks_it);
                pending_ihave -= 1;
                DPRINTF(DEBUG_LEECHER, "Will download chunk %d (%s) from seeder #%d\n",
                        download->chunk->id,
                        download->chunk->hash_str_short,
                        seeder->peer->id);
                DPRINTF(DEBUG_LEECHER, "Pending IHAVE's: %d\n", pending_ihave);
                break;
            }
        }
        ITER_END(hashes_it);
    }
    ITER_END(pending_chunks_it);
    
    // Start sending GET to the seeders if all IHAVE replies were received
    if (pending_ihave == 0)
    {
        DPRINTF(DEBUG_LEECHER, "All IHAVE replies have been received. Start sending GET\n");
        // FIXME: send GET to only |max_conn| number of seeders
        ITER_LOOP(seeder_list_it, seeder_list)
        {
            seeder_t* seeder = iter_get_item(seeder_list_it);
            // Start downloading from the top of the list
            download_t* dl = get_head(seeder->download_list);
            // Send GET to this seeder
            send_get_packet(dl, seeder, sock);
        }
        ITER_END(seeder_list_it);
    }
}


void handle_DATA(PACKET_ARGS)
{
    // See if the sender is actually a registered seeder
    seeder_t* seeder = NULL;
    Node* seeder_node = NULL;
    ITER_LOOP(seeder_it, seeder_list)
    {
        seeder_t* s = iter_get_item(seeder_it);
        if (s->peer->id == from->id)
        {
            seeder = s;
            seeder_node = iter_get_node(seeder_it);
            break;
        }
    }
    ITER_END(seeder_it);
    
    // We don't have anything to do with this peer
    if (!seeder)
    {
        DPRINTF(DEBUG_LEECHER, "Ignore unexpected DATA packet\n");
        return;
    }
    
    // Update the active download
    download_t* dl = get_head(seeder->download_list);
    Node* dl_node = get_head_node(seeder->download_list);
    DPRINTF(DEBUG_LEECHER, "Continue downloading chunk %d (%s) from seeder %d\n",
            dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
    
    if (seq_no == dl->next_packet)
    {
        DPRINTF(DEBUG_LEECHER, "Got the next DATA packet with seq_no=%d\n", seq_no);
        // Reply ACK
        uint8_t* ack_packet = make_empty_packet();
        make_generic_header(ack_packet);
        set_packet_type(ack_packet, PTYPE_ACK);
        set_ack_no(ack_packet, seq_no);
        print_packet_header(DEBUG_LEECHER, ack_packet);
        send_packet(sock, ack_packet, &from->addr);
        DPRINTF(DEBUG_LEECHER, "Sent ACK packet with ack_no=%d\n", get_ack_no(ack_packet));
        free(ack_packet);
        
        // More data to download
        if (dl->remaining_bytes > MAX_PAYLOAD_LEN)
        {
            dl->remaining_bytes -= payload_len;
            dl->next_packet += 1;
            int remaining_packets = ceil((double) dl->remaining_bytes / MAX_PAYLOAD_LEN);
            DPRINTF(DEBUG_LEECHER, "Waiting for %d more DATA packets\n", remaining_packets);
        }
        // Received data packet was the last one
        else
        {
            // FIXME: checksum downloaded chunk using SHA1?
            DPRINTF(DEBUG_LEECHER, "Received DATA packet was the last one\n");
            // This download has finished
            free(drop_node(seeder->download_list, dl_node));
            // More queued downloads from this seeder
            DPRINTF(DEBUG_LEECHER, "Number of pending downloads from seeder %d: %d\n",
                    seeder->peer->id, seeder->download_list->size);
            if (seeder->download_list->size > 0)
            {
                // Send GET (next chunk to download) to this seeder
                send_get_packet(get_head(seeder->download_list), seeder, sock);
            }
            // We want nothing else from this seeder
            else
            {
                DPRINTF(DEBUG_LEECHER, "Downloads from seeder %d has completed\n", seeder->peer->id);
                delete_empty_list(seeder->download_list);
                free(drop_node(seeder_list, seeder_node));
            }
        }
    }
    // Unexpected seq number
    // FIXME: deal with this case !!!
    else
    {}
}



void handle_DENIED(PACKET_ARGS)
{}
