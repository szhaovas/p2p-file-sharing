//
//  peer-leecher.c
//
#include <assert.h>
#include <math.h>
#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include "bt_parse.h"
#include "chunk.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-leecher.h"


/* A seeder is a peer from whom we download a list of chunks */
typedef struct _seeder_t {
    bt_peer_t* peer;
    LinkedList* download_queue;
} seeder_t;

/* Download object for each chunk */
typedef struct _download_t {
    uint32_t next_packet;
    uint64_t remaining_bytes;
    chunk_t* chunk;
    uint8_t data[BT_CHUNK_SIZE];
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
    dl->remaining_bytes = BT_CHUNK_SIZE;
    uint8_t* packet = make_empty_packet();
    make_generic_header(packet);
    set_packet_type(packet, PTYPE_GET);
    set_payload(packet, dl->chunk->hash, SHA1_HASH_SIZE);
    send_packet(sock, packet, &seeder->peer->addr);
    DPRINTF(DEBUG_LEECHER, "GET chunk %i (%s) from seeder %d\n",
            dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
    free(packet);
}


void send_ack_packet(seeder_t* seeder, uint32_t ack_no, int sock)
{
    uint8_t* packet = make_empty_packet();
    make_generic_header(packet);
    set_packet_type(packet, PTYPE_ACK);
    set_ack_no(packet, ack_no);
    send_packet(sock, packet, &seeder->peer->addr);
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
        seeder->download_queue = new_list();
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
                download_t* dl = malloc(sizeof(download_t));
                dl->chunk = pending_chunk;
                // Add the download object to the peer's download list
                insert_tail(seeder->download_queue, dl);
                // Mark this chunk as no longer pending
                iter_drop_curr(pending_chunks_it);
                pending_ihave -= 1;
                DPRINTF(DEBUG_LEECHER, "Will download chunk %d (%s) from seeder #%d\n",
                        dl->chunk->id,
                        dl->chunk->hash_str_short,
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
        DPRINTF(DEBUG_LEECHER, "All IHAVE replies have been received. Start sending GET\n\n");
        // FIXME: send GET to only |max_conn| number of seeders
        ITER_LOOP(seeder_list_it, seeder_list)
        {
            seeder_t* seeder = iter_get_item(seeder_list_it);
            // Start downloading from the top of the list
            download_t* dl = get_head(seeder->download_queue);
            // Send GET to this seeder
            send_get_packet(dl, seeder, sock);
        }
        ITER_END(seeder_list_it);
    }
    DPRINTF(DEBUG_LEECHER, "\n");
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
        DPRINTF(DEBUG_LEECHER, "Ignore unexpected DATA from peer %d\n", from->id);
        return;
    }
    
    download_t* dl = get_head(seeder->download_queue);
    Node* dl_node  = get_head_node(seeder->download_queue);
    
    // FIXME: what to do if we receive more data than expected?
    assert(dl->remaining_bytes >= payload_len);
    
    if (seq_no == dl->next_packet) // We expect this DATA packet
    {
        DPRINTF(DEBUG_LEECHER_RELIABLE, "%3d DATA received\n", seq_no);
        
        send_ack_packet(seeder, seq_no, sock);
        DPRINTF(DEBUG_LEECHER_RELIABLE, "%3d ACK sent\n", get_ack_no(packet));
        
        // Copy payload data to local buffer
        size_t offset = BT_CHUNK_SIZE - dl->remaining_bytes;
        memcpy(dl->data + offset, payload, payload_len);
        dl->remaining_bytes -= payload_len;
        dl->next_packet += 1;
        
        // Last DATA packet received
        if (dl->remaining_bytes == 0)
        {
            DPRINTF(DEBUG_SEEDER, "Last DATA received\n");
            DPRINTF(DEBUG_SEEDER, "Finished leeching chunk %d (%s) from seeder %d\n",
                    dl->chunk->id,
                    dl->chunk->hash_str_short,
                    seeder->peer->id);
            
            // Checksum downloaded chunk
            uint8_t hash_checksum[SHA1_HASH_SIZE+1];
            shahash(dl->data, sizeof(dl->data), hash_checksum);
            DPRINTF(DEBUG_LEECHER, "Computed hash ");
            print_short_hash_str(DEBUG_LEECHER, hash_checksum);
            DPRINTF(DEBUG_LEECHER, ", expecting %s\n", dl->chunk->hash_str_short);
            // GET the chunk again if checksum failed
            if (memcmp(hash_checksum, dl->chunk->hash, SHA1_HASH_SIZE))
            {
                DPRINTF(DEBUG_LEECHER, "Checksum failed. Re-download chunk %d (%s) from seeder %d\n",
                        dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
                send_get_packet(dl, seeder, sock);
            }
            else // Checksum passed
            {
                DPRINTF(DEBUG_LEECHER, "Checksum passed. Writing downloaded chunk %d to data file: %s\n",
                        dl->chunk->id, dl->chunk->data_file);
                // Commit downloaded chunk to disk
                FILE* output = fopen(dl->chunk->data_file, "a");
                if (!output)
                {
                    perror("Could not open data file to write downloaded chunk");
                    // FIXME: Do more!
                }
                if (fseek(output, BT_CHUNK_SIZE * dl->chunk->id, SEEK_SET) < 0)
                {
                    perror("Could not seek to desired offset in data file");
                    // FIXME: Do more!
                }
                ssize_t bytes = fwrite(dl->data, sizeof(uint8_t), sizeof(dl->data), output);
                if (bytes != sizeof(dl->data))
                {
                    perror("Could not write downloaded chunk to data file");
                    // FIXME: Do more!
                }
                fclose(output);
                
                // Remove downloaded chunk from seeder's download list
                // and add it to the list of owned chunks
                insert_tail(owned_chunks, dl->chunk);
                print_owned_chunk(DEBUG_LEECHER);
                free(drop_node(seeder->download_queue, dl_node));
                
                DPRINTF(DEBUG_LEECHER, "Number of pending downloads from seeder %d: %d\n\n",
                        seeder->peer->id, seeder->download_queue->size);
                // More queued downloads from this seeder
                if (seeder->download_queue->size > 0)
                {
                    // Send GET (next chunk in the download queue) to this seeder
                    send_get_packet(get_head(seeder->download_queue), seeder, sock);
                }
                // We got everything we needed from this seeder
                else
                {
                    DPRINTF(DEBUG_LEECHER, "No more downloads from seeder %d\n", seeder->peer->id);
                    delete_empty_list(seeder->download_queue);
                    free(drop_node(seeder_list, seeder_node));
                }
            }
        DPRINTF(DEBUG_LEECHER, "\n");
        }
    }
    // Unexpected seq number
    // FIXME: deal with this case !!!
    else
    {}
}



void handle_DENIED(PACKET_ARGS)
{}
