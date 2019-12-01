//
//  peer-seeder.c
//

#include <string.h> // memcmp()
#include <stdlib.h> // malloc()
#include "bt_parse.h"
#include "debug.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-seeder.h"


void handle_WHOHAS(PACKET_ARGS)
{
    LinkedList* hashes = get_hashes(payload);
    // Filter the hashes that we own
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


void handle_GET(PACKET_ARGS)
{}


void handle_ACK(PACKET_ARGS)
{}
