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
#define INIT_SSTHRESH 8
#define FAULTY_ACK_TOLERANCE 3

typedef struct _leecher_t {
    bt_peer_t* peer;
    chunk_t* seed_chunk;
    int num_faulty_ack;
    uint32_t prev_cw_size;
    double cw_size;
    double ssthresh;
    uint32_t next_ack;
    uint32_t next_to_send;
    uint32_t total_packets;
    uint8_t data[BT_CHUNK_SIZE];
    uint64_t last_active;
    int attempts;
} leecher_t;

LinkedList* leecher_list = NULL;

void handle_WHOHAS(PACKET_ARGS)
{
    // ??? FIXME: Do not respond if already seeding to |max_conn| number of peers
    
    LinkedList* hashes = get_hashes(payload);
    // Filter the hashes we own
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


void send_next_window(leecher_t* leecher, int sock)
{
    
    uint64_t offset, data_len;
    uint32_t cw_size_int = (uint32_t) floor(leecher->cw_size);
    while (leecher->next_to_send < leecher->total_packets &&
           leecher->next_to_send - leecher->next_ack < cw_size_int)
    {
        offset = leecher->next_to_send * DATA_PAYLOAD_LEN;
        uint64_t remaining_bytes = BT_CHUNK_SIZE - offset;
        data_len = fmin(DATA_PAYLOAD_LEN, remaining_bytes);
        
        DPRINTF(DEBUG_SEEDER, "cw_size(%3d): %.3f",
                leecher->next_to_send,
                leecher->cw_size);
        
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%3d/%d DATA sent: ",
                leecher->next_to_send,
                leecher->total_packets);
        
        send_data(leecher->next_to_send,
              leecher->data + offset,
              data_len,
              leecher->peer,
              sock);
    
        remaining_bytes -= data_len;
        leecher->next_to_send += 1;
    }
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
    if (leecher)
    {
        DPRINTF(DEBUG_SEEDER, "Dropping old connection with leecher %d\n", leecher->peer->id);
        free(drop_node(leecher_list, leecher_node));
        return;
    }
    
    // Initialize leecher
    leecher = malloc(sizeof(leecher_t));
    memset(leecher, '\0', sizeof(leecher_t));
    leecher->peer = from;
    leecher->seed_chunk = seed_chunk;
    leecher->next_ack = 0;
    leecher->next_to_send = 0;
    leecher->num_faulty_ack = 0;
    leecher->prev_cw_size = 0;
    leecher->cw_size = 1;
    leecher->ssthresh = INIT_SSTHRESH;
    leecher->total_packets = ceil((double) BT_CHUNK_SIZE / DATA_PAYLOAD_LEN);
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
    send_next_window(leecher, config->sock);
}


// check if cw_size changes and print accordingly
void print_to_plot(leecher_t* leecher, bt_config_t* config) {
    double cw_size_diff = leecher->cw_size - leecher->prev_cw_size;
    if (cw_size_diff >= 1 || cw_size_diff < 0) {
        uint64_t time = get_time_milli() - config->launch_time;
        uint32_t cw_size_int = (uint32_t) floor(leecher->cw_size);
        FILE* cw_plot = fopen(config->cw_plot_file, "a");
        fprintf(cw_plot, "%d\t%llu\t%d\n", leecher->seed_chunk->id, time, cw_size_int);
        fclose(cw_plot);
    }
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
    
    if (ack_no >= leecher->next_ack) // Accumulative ack
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%3d/%d ACK received\n", ack_no, leecher->total_packets);
        leecher->num_faulty_ack = 0;
        // modify cw_size
        leecher->prev_cw_size = (uint32_t) floor(leecher->cw_size);
        if (leecher->cw_size < leecher->ssthresh) {
            leecher->cw_size += 1;
        }
        else {
            leecher->cw_size = leecher->cw_size + 1/leecher->cw_size;
        }
        print_to_plot(leecher, config);
        leecher->attempts = 0;
        leecher->last_active = get_time();
        leecher->next_ack = ack_no + 1;
        
        // Ack'ed data packet was the last one
        // => We are done seeding, so remove this leecher from the list
        if (ack_no + 1 == leecher->total_packets)
        {
            DPRINTF(DEBUG_SEEDER, "Last ACK received.\n");
            DPRINTF(DEBUG_SEEDER, "Finished seeding chunk %d (%s) to leecher %d\n",
                    leecher->seed_chunk->id,
                    leecher->seed_chunk->hash_str_short,
                    leecher->peer->id);
            free(drop_node(leecher_list, leecher_node));
            DPRINTF(DEBUG_SEEDER, "\n");
        }
        else
        {
            // Send data packets if any
            send_next_window(leecher, config->sock);
        }
    
    }
    // Received duplicated ACK
    else if (ack_no + 1 == leecher->next_ack)
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "Dup ACK: Retry (attempt %d/%d)\n", leecher->attempts, RELIABLE_RETRY);
        leecher->num_faulty_ack += 1;
        if (leecher->num_faulty_ack >= FAULTY_ACK_TOLERANCE) { // Fast retransmission
            leecher->next_to_send = ack_no + 1;
            // fast recovery
            leecher->prev_cw_size = (uint32_t) floor(leecher->cw_size);
            leecher->ssthresh = fmax(leecher->cw_size/2, 1);
            leecher->cw_size = leecher->ssthresh;
            print_to_plot(leecher, config);
            send_next_window(leecher, config->sock);
        }
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
    ITER_LOOP(leecher_it, leecher_list)
    {
        leecher_t* leecher = iter_get_item(leecher_it);
        uint64_t now = get_time();
        uint64_t last_active = leecher->last_active;
        assert (last_active <= now);
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
                DPRINTF(DEBUG_SEEDER, "TIMEOUT: Retry (attempt %d/%d)\n", leecher->attempts, RELIABLE_RETRY);
                leecher->next_to_send = leecher->next_ack; // Go back N (go back to last not acked)
                // slow start
                leecher->prev_cw_size = (uint32_t) floor(leecher->cw_size);
                leecher->ssthresh = fmax(leecher->cw_size/2, 1);
                leecher->cw_size = 1;
                print_to_plot(leecher, config);
                send_next_window(leecher, config->sock);
            }
        }
    }
    ITER_END(leecher_it);
}
