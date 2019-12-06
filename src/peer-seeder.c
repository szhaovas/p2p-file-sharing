//
//  peer-seeder.c
//

#include <math.h>
#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include "bt_parse.h"
#include "chunk.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-seeder.h"

#define DATA_PAYLOAD_LEN 1024


typedef struct _leecher_t {
    bt_peer_t* peer;
    chunk_t* seed_chunk;
    uint32_t next_packet;
    uint32_t total_packets;
    uint64_t remaining_bytes;
    uint8_t data[BT_CHUNK_SIZE];
} leecher_t;

LinkedList* leecher_list = NULL;


void handle_WHOHAS(PACKET_ARGS)
{
    // ??? FIXME: Do not respond if already seeding to |max_conn| number of peers
    
    LinkedList* hashes = get_hashes(payload);
    // Filter the owned hashes we own
    LinkedList* matched_chunks = new_list();
    ITER_LOOP(hashes_it, hashes)
    {
        uint8_t* hash = iter_get_item(hashes_it);
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* chunk = iter_get_item(owned_chunks_it);
            if (!memcmp(hash, chunk->hash, SHA1_HASH_SIZE))
            {
                insert_tail(matched_chunks, chunk);
                // No need to free individual hashes since they were not malloc'ed by get_hashes()
                iter_drop_curr(hashes_it);
                break;
            }
        }
        ITER_END(owned_chunks_it);
    }
    ITER_END(hashes_it);
    delete_list(hashes);
    
    // We can seed some of the requested chunks
    if (matched_chunks->size)
    {
        // Construct IHAVE packets
        LinkedList* packets = make_hash_packets(&matched_chunks);
        ITER_LOOP(packets_it, packets)
        {
            uint8_t* packet = iter_get_item(packets_it);
            // Set fields
            make_generic_header(packet);
            set_packet_type(packet, PTYPE_IHAVE);
            // Print packet
            DPRINTF(DEBUG_SEEDER, "Sending IHAVE to peer %d\n", from->id);
            print_hash_payload(DEBUG_SEEDER, packet);
            // Send packet
            if (send_packet(sock, packet, &from->addr) < 0)
            {
                perror("Could not send WHOHAS packet");
            }
            free(iter_drop_curr(packets_it));
        }
        ITER_END(packets_it);
        delete_empty_list(packets);
    }
    // No need to free individual hashes since they were not malloc'ed
    delete_list(matched_chunks);
}


void send_next_data_packet(leecher_t* leecher, int sock)
{
    uint8_t* packet = make_empty_packet();
    make_generic_header(packet);
    set_packet_type(packet, PTYPE_DATA);
    uint64_t offset = (uint64_t) leecher->next_packet * DATA_PAYLOAD_LEN;
    uint64_t bytes = fmin(DATA_PAYLOAD_LEN, leecher->remaining_bytes);
    set_payload(packet, leecher->data + offset, bytes);
    set_seq_no(packet, leecher->next_packet);
    send_packet(sock, packet, &leecher->peer->addr);
    free(packet);
}


void handle_GET(PACKET_ARGS)
{
    // Do not respond if already seeding to |max_conn|
    if (leecher_list && leecher_list->size >= config->max_conn)
        return;
    
    uint8_t* hash = payload;
    DPRINTF(DEBUG_SEEDER, "Peer %d wants hash ", from->id);
    print_short_hash_str(DEBUG_SEEDER, hash);
    DPRINTF(DEBUG_SEEDER, "\n");
    
    // Locate the requested chunk in the owned chunks
    chunk_t* seed_chunk = NULL;
    ITER_LOOP(owned_chunks_it, owned_chunks)
    {
        chunk_t* owned_chunk = iter_get_item(owned_chunks_it);
        if (!memcmp(owned_chunk->hash, hash, SHA1_HASH_SIZE))
        {
            seed_chunk = owned_chunk;
            break;
        }
    }
    ITER_END(owned_chunks_it);
    
    // Ignore the request if we don't actually own the requested chunk
    if (!seed_chunk)
    {
        DPRINTF(DEBUG_SEEDER, "I don't own this chunk\n");
        return;
    }
    
    if (!leecher_list)
        leecher_list = new_list();
    
    // Ignore if the sender is already on the leecher list (only one connection allowed)
    leecher_t* leecher = NULL;
    ITER_LOOP(leecher_it, leecher_list)
    {
        leecher_t* l = iter_get_item(leecher_it);
        if (l->peer->id == from->id)
        {
            leecher = l;
            break;
        }
    }
    ITER_END(leecher_it);
    if (leecher)
    {
        DPRINTF(DEBUG_SEEDER, "Already have another connection with leecher %d\n", leecher->peer->id);
        return;
    }
    
    
    // Send first data packet
    leecher = malloc(sizeof(leecher_t));
    leecher->peer = from;
    leecher->seed_chunk = seed_chunk;
    leecher->next_packet = 0;
    leecher->remaining_bytes = BT_CHUNK_SIZE;
    leecher->total_packets = ceil((double) leecher->remaining_bytes / DATA_PAYLOAD_LEN);
    DPRINTF(DEBUG_SEEDER, "Seeding chunk %d (%s) to leecher %d\n",
            leecher->seed_chunk->id, leecher->seed_chunk->hash_str_short, leecher->peer->id);
    
    // Read chunk data into the buffer
    FILE* fp = fopen(config->data_file, "r");
    if (!fp) return; // FIXME: handle this error
    fseek(fp, leecher->seed_chunk->id * BT_CHUNK_SIZE, SEEK_SET);
    fread(leecher->data, sizeof(uint8_t), BT_CHUNK_SIZE, fp);
    fclose(fp);
    insert_tail(leecher_list, leecher);
    send_next_data_packet(leecher, sock);
}


void handle_ACK(PACKET_ARGS)
{
    // See if the sender is actually a registered leecher
    leecher_t* leecher = NULL;
    Node* leecher_node = NULL;
    ITER_LOOP(leecher_it, leecher_list)
    {
        leecher_t* l = iter_get_item(leecher_it);
        if (l->peer->id == from->id)
        {
            leecher = l;
            leecher_node = iter_get_node(leecher_it);
            break;
        }
    }
    ITER_END(leecher_it);
    
    // We don't have anything to do with this peer
    if (!leecher)
    {
        DPRINTF(DEBUG_SEEDER, "Ignore unexpected ACK from peer %d\n", from->id);
        return;
    }
    
    if (ack_no == leecher->next_packet)
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%3d/%d ACK received\n",
                ack_no,
                leecher->total_packets);
        // More data packets to send
        if (leecher->remaining_bytes > DATA_PAYLOAD_LEN)
        {
            leecher->next_packet += 1;
            leecher->remaining_bytes -= DATA_PAYLOAD_LEN;
            send_next_data_packet(leecher, sock);
            DPRINTF(DEBUG_SEEDER_RELIABLE, "%3d/%d DATA sent\n",
                    leecher->next_packet,
                    leecher->total_packets);
        }
        // Ack'ed data packet was the last one
        // => We are done seeding, so remove this leecher from the list
        else
        {
            DPRINTF(DEBUG_SEEDER, "Last ACK received.\n");
            DPRINTF(DEBUG_SEEDER, "Finished seeding chunk %d (%s) to leecher %d\n",
                    leecher->seed_chunk->id,
                    leecher->seed_chunk->hash_str_short,
                    leecher->peer->id);
            free(drop_node(leecher_list, leecher_node));
            DPRINTF(DEBUG_SEEDER, "\n");
        }
    }
    // Unexpected ack number
    // FIXME: deal with this case !!!
    else
    {}
}
