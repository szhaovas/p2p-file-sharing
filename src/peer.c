/*
 * peer.c
 */

#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "debug.h"
#include "spiffy.h"
#include "bt_parse.h"
#include "input_buffer.h"
#include "chunk.h"
#include "sha.h"
#include "packet.h"
#include "linked-list.h"
#include "peer-proto.h" // handle_packet()


bt_config_t config;
LinkedList* owned_chunks;
int sock;


void peer_run(bt_config_t* config);
int read_chunk_file(char* chunk_file, LinkedList* chunk_list);
bt_peer_t* find_peer_with_addr(struct sockaddr_in* addr);


int main(int argc, char* *argv) {

    bt_init(&config, argc, argv);

    DPRINTF(DEBUG_INIT, "peer.c main beginning\n");

#ifdef TESTING
    config.identity = 1; // your group number here
    strcpy(config.chunk_file, "chunkfile");
    strcpy(config.has_chunk_file, "haschunks");
#endif

    bt_parse_command_line(&config);

#ifdef DEBUG
    if (debug & DEBUG_INIT) {
        bt_dump_config(&config);
    }
#endif

    peer_run(&config);
    return 0;
}


bt_peer_t* find_peer_with_addr(struct sockaddr_in* addr)
{
    bt_peer_t* found = NULL;
    for (bt_peer_t* peer = config.peers; peer; peer = peer->next)
    {
        if (!memcmp(&peer->addr.sin_addr, &addr->sin_addr, sizeof(addr->sin_addr))
            && !memcmp(&peer->addr.sin_port, &addr->sin_port, sizeof(addr->sin_port))
            && !memcmp(&peer->addr.sin_family, &addr->sin_family, sizeof(addr->sin_family)))
        {
            found = peer;
            break;
        }
    }
    return found;
}


int read_chunk_file(char* chunk_file, LinkedList* chunk_list)
{
    FILE* fp;
    ssize_t read;
    fp = fopen(chunk_file, "r");
    if (fp == NULL)
        return -1;
    
    while (1)
    {
        chunk_t* chunk = malloc(sizeof(chunk_t));
        char hash_str[SHA1_HASH_STR_SIZE+1];
        read = fscanf(fp, "%hu %40c", &chunk->id, hash_str);
        if (read == EOF) break;
        else if (read != 2)
        {
            fclose(fp);
            return -1;
        }
        hex2binary(hash_str, SHA1_HASH_SIZE*2, chunk->hash);
        add_item(chunk_list, chunk);
     }
    fclose(fp);
    return 0;
}


void process_inbound_udp(int sock) {
    struct sockaddr_in from;
    socklen_t fromlen;
    uint8_t buf[MAX_PACKET_LEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, MAX_PACKET_LEN, 0, (struct sockaddr *) &from, &fromlen);

    printf("Incoming message from %s:%d\n%s\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf);
    bt_peer_t* peer = find_peer_with_addr(&from);
    if (peer)
        handle_packet(buf, owned_chunks, sock, peer); // handled by peer-proto.c
}


void process_get(char* chunkfile, char* outputfile) {
    DPRINTF(DEBUG_CMD_GET, "Processing GET command\n");
    LinkedList* missing_chunks = new_list();
    if (read_chunk_file(chunkfile, missing_chunks) < 0)
    {
        perror("process_get could not open chunkfile");
        return;
    }
    // Drop already owned chunks in missing_chunks
    ITER_LOOP(missing_chunks_it, missing_chunks)
    {
        chunk_t* missing_chunk = (chunk_t*) iter_get_item(missing_chunks_it);
        int found = 0;
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* owned_chunk = (chunk_t*) iter_get_item(owned_chunks_it);
            if (!memcmp(owned_chunk->hash, missing_chunk->hash, SHA1_HASH_SIZE))
            {
                found = 1;
                break;
            }
        }
        ITER_END(owned_chunks_it);
        if (!found)
        {
            DPRINTF(DEBUG_CMD_GET, "Don't have #%hu ", missing_chunk->id);
            print_hex(DEBUG_CMD_GET, missing_chunk->hash, SHA1_HASH_SIZE);
            DPRINTF(DEBUG_CMD_GET, "\n");
        }
        else
        {
            DPRINTF(DEBUG_CMD_GET, "Already have #%hu ", missing_chunk->id);
            print_hex(DEBUG_CMD_GET, missing_chunk->hash, SHA1_HASH_SIZE);
            DPRINTF(DEBUG_CMD_GET, "\n");
            free(iter_drop_curr(missing_chunks_it));
        }
    }
    ITER_END(missing_chunks_it);
    
    // Construct WHOHAS packets
    LinkedList* packets = make_hash_packets(&missing_chunks);
    ITER_LOOP(packets_it, packets)
    {
        uint8_t* packet = (uint8_t*) iter_get_item(packets_it);
        // Set fields
        make_generic_header(packet);
        set_packet_type(packet, PTYPE_WHOHAS);
        // Print packet contents
        print_packet_header(DEBUG_CMD_GET, packet);
        print_hash_payload(DEBUG_CMD_GET, packet);
        // Send packet
        
        for (bt_peer_t* peer = config.peers; peer; peer = peer->next)
        {
            if (peer->id == config.identity) continue;
            if (send_packet(sock, packet, &peer->addr) < 0)
            {
                perror("process_get could not send packet");
            }
        }
        free(iter_drop_curr(packets_it));
    }
    ITER_END(packets_it);
    delete_empty_list(packets);
    // FIXME: return missing_chunks, or set it to some global var
}


void handle_user_input(char* line, void* cbdata) {
    char chunkf[128], outf[128];

    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));

    if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
        if (strlen(outf) > 0) {
            process_get(chunkf, outf);
        }
    }
}


void peer_run(bt_config_t* config) {
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf* userbuf;
    
    owned_chunks = new_list();
    if (read_chunk_file(config->has_chunk_file, owned_chunks) < 0)
    {
        perror("peer_run could not read has_chunk_file");
        exit(-1);
    }

    if ((userbuf = create_userbuf()) == NULL) {
        perror("peer_run could not allocate userbuf");
        exit(-1);
    }

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) == -1) {
        perror("peer_run could not create socket");
        exit(-1);
    }

    bzero(&myaddr, sizeof(myaddr));
    myaddr.sin_family = AF_INET;
    myaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    myaddr.sin_port = htons(config->myport);

    if (bind(sock, (struct sockaddr *) &myaddr, sizeof(myaddr)) == -1) {
        perror("peer_run could not bind socket");
        exit(-1);
    }

    spiffy_init(config->identity, (struct sockaddr *) &myaddr, sizeof(myaddr));

    while (1) {
        int nfds;
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);

        nfds = select(sock+1, &readfds, NULL, NULL, NULL);

        if (nfds > 0) {
            if (FD_ISSET(sock, &readfds)) {
                process_inbound_udp(sock);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                                   "Currently unused");
            }
        }
    }
}
