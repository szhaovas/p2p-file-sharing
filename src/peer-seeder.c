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
#define SLOW_START_THRESH 64
#define FAST_RETRAN_ACKS 3


typedef struct _window_t {
    uint32_t next_ack;
    uint32_t next_to_send;
    uint32_t total_packets;
    double cw;
    double cw_prev;
    double ssthresh;
} window_t;

typedef struct _leecher_t {
    bt_peer_t* peer;
    chunk_t* seed_chunk;
    int num_dup_ack;
    window_t window;
    uint8_t data[BT_CHUNK_SIZE];
    uint64_t last_active;
    int attempts;
} leecher_t;

LinkedList* leecher_list = NULL;



uint32_t get_flow_no(leecher_t* leecher)
{
#define LEECHER_ID_OFFSET 1000
    return leecher->peer->id * LEECHER_ID_OFFSET + leecher->seed_chunk->id;
}


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


void init_window(window_t* window)
{
    window->next_ack = 0;
    window->next_to_send = 0;
    window->cw_prev = 0;
    window->cw = 1;
    window->ssthresh = SLOW_START_THRESH;
    window->total_packets = ceil((double) BT_CHUNK_SIZE / DATA_PAYLOAD_LEN);
}


void send_next_window(leecher_t* leecher, int sock)
{
    
    uint64_t offset, data_len;
    window_t* w = &leecher->window;
    uint32_t cw_int = floor(w->cw);
    while (w->next_to_send < w->total_packets &&
           w->next_to_send - w->next_ack < cw_int)
    {
        offset = w->next_to_send * DATA_PAYLOAD_LEN;
        uint64_t remaining_bytes = BT_CHUNK_SIZE - offset;
        data_len = fmin(DATA_PAYLOAD_LEN, remaining_bytes);
        
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%d: %3d/%d DATA sent\n",
                leecher->peer->id,
                w->next_to_send,
                w->total_packets);
        
        send_data(w->next_to_send,
                  leecher->data + offset,
                  data_len,
                  leecher->peer,
                  sock);
    
        remaining_bytes -= data_len;
        w->next_to_send += 1;
    }
    
    leecher->attempts += 1;
    leecher->last_active = get_time();
}


void send_next_packet(leecher_t* leecher, int sock)
{
    double cw_copy = leecher->window.cw;
    leecher->window.cw = 1;
    send_next_window(leecher, sock);
    leecher->window.cw = cw_copy;
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
    leecher->num_dup_ack = 0;
    leecher->attempts = 0;
    init_window(&leecher->window);
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


/**
 Print congestion window if it changed.
 */
void print_cw_plot(leecher_t* leecher, bt_config_t* config)
{
    window_t* window = &leecher->window;
    int cw_diff = (int) window->cw - (int) window->cw_prev;
    if (cw_diff != 0)
    {
        FILE* cw_plot = fopen(config->cw_plot_file, "a");
        if (!cw_plot)
        {
            perror("Could not write to congestion window file");
            return;
        }
        fprintf(cw_plot, "f%d\t%llu\t%d\n",
                get_flow_no(leecher),
                get_time_msec() - config->launch_time,
                (int) floor(window->cw));
        fclose(cw_plot);
    }
}


void adjust_window_ack(leecher_t* leecher, uint32_t ack_no, bt_config_t* config)
{
    window_t* window = &leecher->window;
    window->cw_prev = floor(window->cw);
    if (window->cw < window->ssthresh) // Slow start: exponential increase
    {
        window->cw += 1;
    }
    else // AIMD: additive increase
    {
        window->cw = window->cw + 1/window->cw;
    }
    window->next_ack = ack_no + 1;
    print_cw_plot(leecher, config);
}


void adjust_window_loss_timeout(leecher_t* leecher, bt_config_t* config)
{
    window_t* window = &leecher->window;
    window->next_to_send = window->next_ack; // Go back N (go back to last not acked)
    // Go back to slow start
    window->cw_prev = floor(window->cw);
    window->ssthresh = fmax(window->cw/2, 1);
    window->cw = 1;
    print_cw_plot(leecher, config);
}


void adjust_window_loss_dup_ack(leecher_t* leecher, uint32_t ack_no, bt_config_t* config)
{
    window_t* window = &leecher->window;
    window->next_to_send = ack_no + 1;
    // Fast recovery
    window->cw_prev = floor(window->cw);
    window->ssthresh = fmax(window->cw/2, 1);
    window->cw = window->ssthresh;
    print_cw_plot(leecher, config);
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
    
    if (ack_no >= leecher->window.next_ack) // Accumulative ack
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "%d: %3d/%d ACK received\n", leecher->peer->id, ack_no, leecher->window.total_packets);
        leecher->num_dup_ack = 0;
        adjust_window_ack(leecher, ack_no, config);
        leecher->attempts = 0;
        leecher->last_active = get_time();
        
        
        // Ack'ed data packet was the last one
        // => We are done seeding, so remove this leecher from the list
        if (ack_no + 1 == leecher->window.total_packets)
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
    else if (ack_no + 1 == leecher->window.next_ack)
    {
        DPRINTF(DEBUG_SEEDER_RELIABLE, "Dup ACK: Retry (attempt %d/%d)\n", leecher->attempts, RELIABLE_RETRY);
        leecher->num_dup_ack += 1;
        if (leecher->num_dup_ack >= FAST_RETRAN_ACKS) { // Fast retransmission
//            send_next_window(leecher, config->sock);
            send_next_packet(leecher, config->sock);
            adjust_window_loss_dup_ack(leecher, ack_no, config);
            leecher->num_dup_ack = 0;
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
                adjust_window_loss_timeout(leecher, config);
                send_next_window(leecher, config->sock);
            }
        }
    }
    ITER_END(leecher_it);
}
