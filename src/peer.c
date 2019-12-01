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
#include "peer.h"


packet_handler_t handlers[NUM_PACKET_TYPES] = {
    handle_WHOHAS,
    handle_IHAVE,
    handle_GET,
    handle_DATA,
    handle_ACK,
    handle_DENIED
};


/* Forward declarations */
void peer_run(bt_config_t* config);
int read_chunk_file(char* chunk_file, LinkedList* chunk_list);
bt_peer_t* find_peer_with_addr(struct sockaddr_in* addr);
void handle_packet(uint8_t* packet, LinkedList* owned_chunks, int sock, bt_peer_t* from);


/* Global variables */
bt_config_t config;
LinkedList* owned_chunks;
int sock;


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


/**
 Set packet's magic number and version to the implementation-specific numbers.
 */
void make_generic_header(uint8_t* packet)
{
    set_magic_number(packet, MAGIC_NUMBER);
    set_version(packet, VERSION);
}


/**
 Dispatch a packet to the appropriate handler.
 */
void handle_packet(uint8_t* packet, LinkedList* owned_chunks, int sock, bt_peer_t* from)
{
    uint16_t magic_no = get_magic_no(packet);
    uint8_t version = get_version(packet);
    uint8_t packet_type = get_packet_type(packet);
    if (packet_type < NUM_PACKET_TYPES &&
        magic_no == MAGIC_NUMBER && version == VERSION)
    {
        (*handlers[packet_type])(get_seq_no(packet),
                                 get_ack_no(packet),
                                 get_payload(packet),
                                 owned_chunks,
                                 sock,
                                 from);
    }
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
        chunk_t* missing_chunk = iter_get_item(missing_chunks_it);
        DPRINTF(DEBUG_CMD_GET, "Looking for #%hu ", missing_chunk->id);
        print_hex(DEBUG_CMD_GET, missing_chunk->hash, SHA1_HASH_SIZE);
        DPRINTF(DEBUG_CMD_GET, "\n");
        int found = 0;
        ITER_LOOP(owned_chunks_it, owned_chunks)
        {
            chunk_t* owned_chunk = iter_get_item(owned_chunks_it);
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
    if (missing_chunks->size > 0)
    {
        DPRINTF(DEBUG_CMD_GET, "WHOHAS flooding\n");
        flood_WHOHAS(missing_chunks, config.peers, config.identity, sock);
    }
    else
    {
        DPRINTF(DEBUG_CMD_GET, "No need for WHOHAS since already have everything\n");
    }
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
