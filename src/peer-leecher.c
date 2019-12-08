//
//  peer-leecher.c
//
#include <assert.h>
#include <math.h>   // fmin()
#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include "bt_parse.h"
#include "chunk.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-leecher.h"


#define AWAIT_NONE  0
#define AWAIT_IHAVE 1
#define AWAIT_DATA  2

#define DL_STARTING 0 // Upon timeout, should resend GET
#define DL_STARTED  1 // Upon timeout, should resent ACK

#define CLEAN_PENDING 0
#define DO_NOT_CLEAN_PENDING 1


/* A seeder is a peer from whom we download a list of chunks */
typedef struct _seeder_t {
    int state;
    int attempts;
    uint64_t last_active;
    bt_peer_t* peer;
    LinkedList* download_queue;
} seeder_t;

/* Download object for each chunk */
typedef struct _download_t {
    uint32_t expect_packet;
    uint64_t remaining_bytes;
    chunk_t* chunk;
    uint8_t data[BT_CHUNK_SIZE];
} download_t;

int state = AWAIT_NONE;
int pending_ihave = 0;
int whohas_attempts = 0;
int get_attempts = 0;
uint64_t whohas_last_active = 0;
LinkedList* pending_chunks = NULL;
LinkedList* seeder_waitlist = NULL;
LinkedList* active_seeders  = NULL;

void start_download(download_t* dl, seeder_t* seeder, int sock);
void activate_one_seeder(int max_conn, int sock);
int  commit_download_to_file(download_t* dl);
int  downloaded_hash_okay(download_t* dl);
void clean(int should_clean_pending_chunks);


/**
 See if there's an ongoing download.
 */
int ongoing_jobs_exist()
{
    return pending_chunks != NULL;
}


/**
 Download missing chunk.
 */
void get_chunks(LinkedList* missing_chunks, bt_config_t* config)
{
    if (!pending_chunks)
    {
        DPRINTF(DEBUG_LEECHER, "New GET command from the user (attempt %d)\n", get_attempts);
        pending_chunks = missing_chunks;
    }
    else
    {
        DPRINTF(DEBUG_LEECHER, "Retry failed downloads (attempt %d)\n", get_attempts);
    }
    
    get_attempts += 1;
    
    assert(!active_seeders && !seeder_waitlist && state == AWAIT_NONE);
    state = AWAIT_IHAVE;
    pending_ihave = pending_chunks->size;
    active_seeders = new_list();
    seeder_waitlist = new_list();
    
    whohas_attempts = 0;
    DPRINTF(DEBUG_LEECHER, "Flood WHOHAS (attempt %d)\n", whohas_attempts);
    send_whohas(&pending_chunks, config->peers, config->identity, config->sock);
    whohas_attempts += 1;
    whohas_last_active = get_time();
}


void start_download(download_t* dl, seeder_t* seeder, int sock)
{
    dl->expect_packet = 0;
    dl->remaining_bytes = BT_CHUNK_SIZE;
    DPRINTF(DEBUG_LEECHER, "GET chunk %i (%s) from seeder %d\n",
            dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
    send_get(dl->chunk->hash, seeder->peer, sock);
    seeder->state = DL_STARTING;
    seeder->attempts += 1;
    seeder->last_active = get_time();
}


void activate_one_seeder(int max_conn, int sock)
{
    // Make sure there is indeed a seeder waiting to be activated
    assert(active_seeders->size < max_conn);
    assert(seeder_waitlist->size > 0);
    // Move the seeder from waitlist to active list
    seeder_t* seeder = drop_head(seeder_waitlist);
    insert_tail(active_seeders, seeder);
    // Start downloading from this seeder
    download_t* dl = get_head(seeder->download_queue);
    seeder->attempts = 0;
    start_download(dl, seeder, sock);
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
    // Look for the IHAVE sender in the seeder list
    seeder_t* seeder = NULL;
    Node* seeder_node = NULL;
    ITER_LOOP(seeder_it, seeder_waitlist)
    {
        seeder_t* peer_dl = iter_get_item(seeder_it);
        if (peer_dl->peer->id == from->id)
        {
            seeder = peer_dl;
            seeder_node = iter_get_node(seeder_it);
        }
    }
    ITER_END(seeder_it);
    
    // If this is a new seeder, add it to the seeder list
    if (!seeder)
    {
        seeder = malloc(sizeof(seeder_t));
        memset(seeder, '\0', sizeof(seeder_t));
        seeder->peer = from;
        seeder->download_queue = new_list();
        seeder_node = insert_tail(seeder_waitlist, seeder);
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
                memset(dl, '\0', sizeof(download_t));
                dl->chunk = pending_chunk;
                // Add the download object to the peer's download list
                insert_tail(seeder->download_queue, dl);
                // Mark this chunk as no longer pending
                iter_drop_curr(pending_chunks_it);
                pending_ihave -= 1;
                whohas_last_active = get_time();
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
    
    // We need nothing from this seeder
    if (seeder->download_queue->size == 0)
    {
        delete_empty_list(seeder->download_queue);
        free(drop_node(seeder_waitlist, seeder_node));
    }
    
    // Start downloading if all IHAVE replies were received
    if (pending_ihave == 0)
    {
        DPRINTF(DEBUG_LEECHER, "All IHAVE replies have been received. Start the downloads\n");
        state = AWAIT_DATA;
        int num_active_seeders = fmin(config->max_conn, seeder_waitlist->size);
        for (int i = 0; i < num_active_seeders; i++)
        {
            activate_one_seeder(config->max_conn, config->sock);
        }
    }
    DPRINTF(DEBUG_LEECHER, "\n");
}


int commit_download_to_file(download_t* dl)
{
    int rc = 0;
    FILE* output = fopen(dl->chunk->data_file, "a");
    if (!output)
    {
        perror("Could not open data file to write downloaded chunk");
        rc = -1;
    }
    if (fseek(output, BT_CHUNK_SIZE * dl->chunk->id, SEEK_SET) < 0)
    {
        perror("Could not seek to desired offset in data file");
        rc = -1;
    }
    ssize_t bytes = fwrite(dl->data, sizeof(uint8_t), sizeof(dl->data), output);
    if (bytes != sizeof(dl->data))
    {
        perror("Could not write downloaded chunk to data file");
        rc = -1;
    }
    fclose(output);
    return rc;
}


int downloaded_hash_okay(download_t* dl)
{
    // Checksum downloaded chunk
    uint8_t hash_checksum[SHA1_HASH_SIZE+1];
    shahash(dl->data, sizeof(dl->data), hash_checksum);
    DPRINTF(DEBUG_LEECHER, "Computed hash ");
    print_short_hash_str(DEBUG_LEECHER, hash_checksum);
    DPRINTF(DEBUG_LEECHER, ", expecting %s\n", dl->chunk->hash_str_short);
    
    return !memcmp(hash_checksum, dl->chunk->hash, SHA1_HASH_SIZE);
}


void handle_DATA(PACKET_ARGS)
{
    if (!active_seeders)
    {
        DPRINTF(DEBUG_LEECHER, "Ignore unexpected DATA from peer %d\n", from->id);
        return;
    }
    
    // See if the sender is actually an active seeder
    seeder_t* seeder = NULL;
    Node* seeder_node = NULL;
    ITER_LOOP(seeder_it, active_seeders)
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
    
    
    // If this is the first DATA, mark download as already started
    if (seeder->state == DL_STARTING)
    {
        seeder->state = DL_STARTED;
        seeder->attempts = 0;
        DPRINTF(DEBUG_LEECHER_RELIABLE, "Download confirmed by seeder %d\n", seeder->peer->id);
    }
    
    DPRINTF(DEBUG_LEECHER_RELIABLE, "%3d DATA received\n", seq_no);
    
    // Assume packet corruption has occurred and ask for retransimission if
    // (1) we received more data than expected or
    // (2) seq_no is wrong
    if (dl->remaining_bytes < payload_len || seq_no != dl->expect_packet)
    {
        DPRINTF(DEBUG_LEECHER_RELIABLE, "* %3d DATA is corrupted. Dup ack_no=%d (attempts %d)\n",
                seq_no, dl->expect_packet, seeder->attempts);
        // Send duplicated ACK
        send_ack(dl->expect_packet, seeder->peer, config->sock);
        seeder->attempts += 1;
        seeder->last_active = get_time();
    }
    else // We expect this DATA packet
    {
        // Copy payload data to local buffer
        size_t offset = BT_CHUNK_SIZE - dl->remaining_bytes;
        memcpy(dl->data + offset, payload, payload_len);
        dl->remaining_bytes -= payload_len;
        
        // Ack
        dl->expect_packet += 1;
        send_ack(dl->expect_packet, seeder->peer, config->sock);
        seeder->attempts = 1; // reset attempts
        seeder->last_active = get_time();
        DPRINTF(DEBUG_LEECHER_RELIABLE, "%3d ACK sent\n", dl->expect_packet);
        
        // Last DATA packet is received
        if (dl->remaining_bytes == 0)
        {
            DPRINTF(DEBUG_SEEDER, "Last DATA received\n");
            DPRINTF(DEBUG_SEEDER, "Finished leeching chunk %d (%s) from seeder %d\n",
                    dl->chunk->id,
                    dl->chunk->hash_str_short,
                    seeder->peer->id);
            
            if (!downloaded_hash_okay(dl))
            {
                DPRINTF(DEBUG_LEECHER, "Checksum failed. Re-download chunk %d (%s) from seeder %d\n",
                        dl->chunk->id, dl->chunk->hash_str_short, seeder->peer->id);
                start_download(dl, seeder, config->sock);
            }
            else // Hash okay
            {
                DPRINTF(DEBUG_LEECHER, "Checksum passed. Writing downloaded chunk %d to data file: %s\n",
                        dl->chunk->id, dl->chunk->data_file);
                // Failed to write to output file
                if (commit_download_to_file(dl) < 0)
                {
                    DPRINTF(DEBUG_LEECHER, "FATAL: Could not write data to output file\n");
                    clean(CLEAN_PENDING); // FIXME: be more tolerant? What else can we do?
                    return;
                }
                
                // Remove downloaded chunk from seeder's download list
                // and add it to the list of owned chunks
                insert_tail(owned_chunks, dl->chunk);
                print_chunks(DEBUG_LEECHER, owned_chunks);
                free(drop_node(seeder->download_queue, dl_node));
                
                DPRINTF(DEBUG_LEECHER, "Number of pending downloads from seeder %d: %d\n\n",
                        seeder->peer->id, seeder->download_queue->size);
                // More queued downloads from this seeder
                if (seeder->download_queue->size > 0)
                {
                    // Send GET (next chunk in the download queue) to this seeder
                    seeder->attempts = 0;
                    start_download(get_head(seeder->download_queue), seeder, config->sock);
                }
                // Got everything needed from this seeder => Deactivate and remove this seeder
                else
                {
                    DPRINTF(DEBUG_LEECHER, "No more downloads from seeder %d\n", seeder->peer->id);
                    delete_empty_list(seeder->download_queue);
                    free(drop_node(active_seeders, seeder_node));
                    // Activate seeders on the waitlist, if any
                    if (seeder_waitlist->size > 0)
                        activate_one_seeder(config->max_conn,  config->sock);
                    // No seeder on the waitlist
                    else
                    {
                        if (active_seeders->size == 0 && pending_chunks->size == 0) // All downloads have completed
                        {
                            clean(CLEAN_PENDING);
                        }
                        else // Need to retry accumulated failed downloads
                        {
                            clean(DO_NOT_CLEAN_PENDING);
                            get_chunks(NULL, config);
                        }
                    }
                }
            }
            DPRINTF(DEBUG_LEECHER, "\n");
        }
    }
}


void handle_DENIED(PACKET_ARGS)
{}


void clean(int should_clean_pending_chunks)
{
    state = AWAIT_NONE;
    pending_ihave = 0;
    whohas_attempts = 0;
    whohas_last_active = 0;
    get_attempts = 0;
    
    if (should_clean_pending_chunks == CLEAN_PENDING && pending_chunks)
    {
        ITER_LOOP(pending_chunks_it, pending_chunks)
        {
            free(iter_drop_curr(pending_chunks_it));
        }
        ITER_END(pending_chunks_it);
        delete_empty_list(pending_chunks);
        pending_chunks = NULL;
    }
    
    if (active_seeders)
    {
        ITER_LOOP(active_seeders_it, active_seeders)
        {
            seeder_t* seeder = iter_get_item(active_seeders_it);
            ITER_LOOP(dl_it, seeder->download_queue)
            {
                download_t* dl = iter_get_item(dl_it);
                free(dl->chunk);
                free(iter_drop_curr(dl_it));
            }
            ITER_END(dl_it);
            free(iter_drop_curr(active_seeders_it));
        }
        ITER_END(active_seeders_it);
        delete_empty_list(active_seeders);
        active_seeders = NULL;
    }
    
    if (seeder_waitlist)
    {
        ITER_LOOP(seeder_waitlist_it, seeder_waitlist)
        {
            seeder_t* seeder = iter_get_item(seeder_waitlist_it);
            ITER_LOOP(dl_it, seeder->download_queue)
            {
                download_t* dl = iter_get_item(dl_it);
                free(dl->chunk);
                free(iter_drop_curr(dl_it));
            }
            ITER_END(dl_it);
            free(iter_drop_curr(seeder_waitlist_it));
        }
        ITER_END(seeder_waitlist_it);
        delete_empty_list(seeder_waitlist);
        seeder_waitlist = NULL;
    }
}


void leecher_timeout(bt_config_t* config)
{
    switch (state) {
        case AWAIT_IHAVE:
        {
            uint64_t now = get_time();
            assert(now > whohas_last_active);
            if (whohas_attempts >= WHOHAS_RETRY)
            {
                DPRINTF(DEBUG_LEECHER, "AWAIT_IHAVE reached attempts limit (%d/%d)\n",
                        whohas_attempts, WHOHAS_RETRY);
                DPRINTF(DEBUG_LEECHER, "FATAL: Could not gather all IHAVE packets\n");
                clean(CLEAN_PENDING);
            }
            else if (now - whohas_last_active > WHOHAS_TIMEOUT)
            {
                DPRINTF(DEBUG_LEECHER, "AWAIT_IHAVE timeout. Retry...\n");
                DPRINTF(DEBUG_LEECHER, "Flood WHOHAS (attempt %d)\n", whohas_attempts);
                send_whohas(&pending_chunks, config->peers, config->identity, config->sock);
                whohas_attempts += 1;
                whohas_last_active = get_time();
            }
            break;
        }
            
        case AWAIT_DATA:
        {
            ITER_LOOP(active_seeder_it, active_seeders)
            {
                seeder_t* seeder = iter_get_item(active_seeder_it);
                uint64_t now = get_time();
                assert(now > seeder->last_active);
                if (seeder->attempts >= RELIABLE_RETRY)
                {
                    DPRINTF(DEBUG_LEECHER, "Seeder %d reached attempts limit (%d/%d)\n",
                            seeder->peer->id, seeder->attempts, RELIABLE_RETRY);
                    perror("Download failed. Will attempts later");
                    // Move the chunks for which this seeder is responsible to the pending list
                    ITER_LOOP(dl_it, seeder->download_queue)
                    {
                        insert_tail(pending_chunks, iter_drop_curr(dl_it));
                    }
                    ITER_END(dl_it);
                    delete_empty_list(seeder->download_queue);
                    // Remove this seeder completely
                    free(iter_drop_curr(active_seeder_it));
                    // Promote a waitlisted seeder, if any, to the active list
                    if (seeder_waitlist->size > 0)
                        activate_one_seeder(config->max_conn, config->sock);
                }
                else if (now - seeder->last_active > RELIABLE_TIMEOUT)
                {
                    DPRINTF(DEBUG_LEECHER, "Seeder %d download timeout. Retry...\n", seeder->peer->id);
                    download_t* dl = get_head(seeder->download_queue);
                    switch (seeder->state)
                    {
                        case DL_STARTING:
                        {
                            start_download(dl, seeder, config->sock);
                            break;
                        }
                        case DL_STARTED:
                        {
                            send_ack(dl->expect_packet, seeder->peer, config->sock);
                            seeder->attempts += 1;
                            seeder->last_active = get_time();
                            break;
                        }
                        default:
                            break;
                    }
                }
            }
            ITER_END(active_seeder_it);
            if (active_seeders->size == 0)
            {
                clean(DO_NOT_CLEAN_PENDING);
                get_chunks(NULL, config);
            }
            break;
        }
            
        default:
            break;
    }
}

