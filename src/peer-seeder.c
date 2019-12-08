//
//  peer-seeder.c
//

#include <assert.h>
#include <math.h>
#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include <sys/time.h> // gettimeofday()
#include "bt_parse.h"
#include "chunk.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-seeder.h"
#include "peer-reliable.h"

#define DATA_PAYLOAD_LEN 1024


typedef struct _leecher_t {
    bt_peer_t* peer;
    chunk_t* seed_chunk;
    uint32_t next_packet;
    uint32_t total_packets;
    uint64_t remaining_bytes;
    uint8_t data[BT_CHUNK_SIZE];
    uint64_t last_active;
    int attempts;
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
        send_ihave(&matched_chunks, from, config->sock);
    }
    // No need to free individual hashes since they were not malloc'ed
    delete_list(matched_chunks);
}


void send_next_data_packet(leecher_t* leecher, int sock)
{
    uint64_t offset = BT_CHUNK_SIZE - leecher->remaining_bytes;
    uint64_t data_len = fmin(DATA_PAYLOAD_LEN, leecher->remaining_bytes);
    
    send_data(leecher->next_packet,
              leecher->data + offset,
              data_len,
              leecher->peer,
              sock);
    
    leecher->attempts += 1;
    leecher->last_active = get_time();
}


int read_data(leecher_t* leecher, bt_config_t* config)
{
    int rc = 0;
    FILE* fp = fopen(config->data_file, "r");
    if (!fp)
        rc = -1;
    if (fseek(fp, leecher->seed_chunk->id * BT_CHUNK_SIZE, SEEK_SET) < 0)
        rc = -1;
    if (fread(leecher->data, sizeof(uint8_t), BT_CHUNK_SIZE, fp) != BT_CHUNK_SIZE)
        rc = -1;
    fclose(fp);
    return rc;
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
    
    // Initialize leecher
    leecher = malloc(sizeof(leecher_t));
    memset(leecher, '\0', sizeof(leecher_t));
    leecher->peer = from;
    leecher->seed_chunk = seed_chunk;
    leecher->next_packet = 0;
    leecher->remaining_bytes = BT_CHUNK_SIZE;
    leecher->total_packets = ceil((double) leecher->remaining_bytes / DATA_PAYLOAD_LEN);
    leecher->attempts = 0;
    // Read chunk data into the buffer
    if (read_data(leecher, config) < 0)
    {
        free(leecher);
        perror("Seeder could not read data chunk to seed");
        // FIXME: send DENIED ?
    }
    insert_tail(leecher_list, leecher);
    
    // Send first data packet
    DPRINTF(DEBUG_SEEDER, "Seeding chunk %d (%s) to leecher %d\n",
            leecher->seed_chunk->id, leecher->seed_chunk->hash_str_short, leecher->peer->id);
    send_next_data_packet(leecher, config->sock);
}


void handle_ACK(PACKET_ARGS)
{
    if (!leecher_list)
    {
        DPRINTF(DEBUG_SEEDER, "Ignore unexpected ACK from peer %d\n", from->id);
        return;
    }
    
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
    
    if (ack_no == leecher->next_packet + 1)
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%3d/%d ACK received\n",
                ack_no,
                leecher->total_packets);
        leecher->last_active = get_time();
        // More data packets to send
        if (leecher->remaining_bytes > DATA_PAYLOAD_LEN)
        {
            leecher->next_packet += 1;
            leecher->remaining_bytes -= DATA_PAYLOAD_LEN;
            leecher->attempts = 0;
            send_next_data_packet(leecher, config->sock);
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
    // Received duplicated ACK
    else if (ack_no == leecher->next_packet)
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "Retry (attempt %d/%d)\n", leecher->attempts, RELIABLE_RETRY);
        send_next_data_packet(leecher, config->sock);
    }
    // Ignore unexpected ACK no
    else
    {
        DPRINTF(DEBUG_SEEDER, "Did not expect ack_no=%d\n", ack_no);
    }
}


void seeder_timeout(bt_config_t* config)
{
    if (!leecher_list) return;
    struct timeval now;
    gettimeofday(&now, NULL);
    ITER_LOOP(leecher_it, leecher_list)
    {
        leecher_t* leecher = iter_get_item(leecher_it);
        uint64_t now = get_time();
        uint64_t last_active = leecher->last_active;
        assert (last_active < get_time());
        if (now - last_active > RELIABLE_TIMEOUT)
        {
            DPRINTF(DEBUG_SEEDER, "Leecher %d timeout triggered (%llu)\n", leecher->peer->id, now-last_active);
            if (leecher->attempts >= RELIABLE_RETRY)
            {
                DPRINTF(DEBUG_SEEDER, "Leecher %d reached attempts limit (%d/%d)\n",
                leecher->peer->id, leecher->attempts, RELIABLE_RETRY);
                free(iter_drop_curr(leecher_it));
            }
            else
            {
                DPRINTF(DEBUG_SEEDER, "Retry (attempt %d/%d)\n", leecher->attempts, RELIABLE_RETRY);
                send_next_data_packet(leecher, config->sock);
            }
        }
    }
    ITER_END(leecher_it);
}
