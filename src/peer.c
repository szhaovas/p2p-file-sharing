/*
 * peer.c
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h> // malloc()
#include <string.h> // memcmp()
#include <unistd.h> // access()
#include "bt_parse.h"
#include "chunk.h"
#include "debug.h"
#include "spiffy.h"
#include "input_buffer.h"
#include "linked-list.h"
#include "packet.h"
#include "peer.h"
#include "peer-seeder.h"
#include "peer-leecher.h"
#include "sha.h"


/* Forward declarations */
void peer_run(bt_config_t* config);
int read_chunk_file(char* chunk_file, LinkedList* chunk_list);
bt_peer_t* find_peer_with_addr(struct sockaddr_in* addr);


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


void get_short_hash_str(const char* hash_str, char* hash_str_short)
{
#define LEADING_LEN 3
#define TRAILING_LEN 2
    memcpy(hash_str_short, hash_str, LEADING_LEN);
    hash_str_short += LEADING_LEN;
    hash_str_short += sprintf(hash_str_short, "...");
    memcpy(hash_str_short, hash_str + SHA1_HASH_STR_SIZE - TRAILING_LEN, TRAILING_LEN);
}


void print_short_hash_str(int level, uint8_t* hash)
{
    char hash_str[SHA1_HASH_STR_SIZE+1];
    char hash_str_short[SHA1_HASH_STR_SIZE+1];
    memset(hash_str, '\0', SHA1_HASH_STR_SIZE+1);
    memset(hash_str_short, '\0', SHA1_HASH_STR_SIZE+1);
    binary2hex(hash, SHA1_HASH_SIZE, hash_str);
    get_short_hash_str(hash_str, hash_str_short);
    DPRINTF(level, "%s", hash_str_short);
    
}


void print_chunks(int level, LinkedList* chunks)
{
    DPRINTF(level, "Chunks (%d):\n", chunks->size);
    ITER_LOOP(chunk_it, chunks)
    {
        chunk_t* chunk = iter_get_item(chunk_it);
        DPRINTF(level, "%d (%s) at %s\n", chunk->id, chunk->hash_str_short, chunk->data_file);
    }
    ITER_END(chunk_it);
}

int read_chunk_file(char* chunk_file, LinkedList* chunk_list)
{
    int rc = 0;
    FILE* fp;
    ssize_t read;
    fp = fopen(chunk_file, "r");
    if (fp == NULL) return -1;
    while (1)
    {
        chunk_t* chunk = malloc(sizeof(chunk_t));
        memset(chunk, '\0', sizeof(chunk_t));
        read = fscanf(fp, "%hu %40c", &chunk->id, chunk->hash_str);
        if (read == EOF)
        {
            free(chunk);
            rc = 0;
            break;
        }
        else if (read != 2)
        {
            free(chunk);
            rc = -1;
            break;
        }
        hex2binary(chunk->hash_str, SHA1_HASH_SIZE*2, chunk->hash);
        get_short_hash_str(chunk->hash_str, chunk->hash_str_short);
        insert_tail(chunk_list, chunk);
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

//    printf("Incoming message from %s:%d\n\n", inet_ntoa(from.sin_addr), ntohs(from.sin_port));
    bt_peer_t* peer = find_peer_with_addr(&from);
    if (peer)
        handle_packet(buf, owned_chunks, peer, &config);
}


void process_get(char* chunkfile, char* outputfile) {
    DPRINTF(DEBUG_CMD_GET, "Processing GET command\n");
    LinkedList* missing_chunks = new_list();
    if (read_chunk_file(chunkfile, missing_chunks) < 0)
    {
        perror("process_get could not open chunkfile");
        return;
    }
    FILE* fp = fopen(outputfile, "r");
    if (fp) { // File exists. Ask the user if okay to overwrite
        int overwrite = -1;
        printf("Output file (%s) already exists. ", outputfile);
        do {
            printf("Overwrite (y/n)? ");
            char* answer = NULL;
            size_t len;
            if (getline(&answer, &len, stdin) < 0) continue;
            if (len == 0)
            {
                if (answer) free(answer);
                continue;
            }
            switch (answer[0]) {
                case 'y': case 'Y':
                    overwrite = 1;
                    break;
                case 'n': case 'N':
                    overwrite = 0;
                    break;
                default:
                    break;
            }
            free(answer);
        }  while (overwrite < 0);
        fclose(fp);
        if (!overwrite) return;
    }
    fp = fopen(outputfile, "w");
    if (!fp)
    {
        perror("process_get could not open output file for writing");
        return;
    }
    fclose(fp);
    
    
    // Drop already owned chunks in missing_chunks
    ITER_LOOP(missing_chunks_it, missing_chunks)
    {
        chunk_t* missing_chunk = iter_get_item(missing_chunks_it);
        DPRINTF(DEBUG_CMD_GET, "Looking for #%hu %s\n",
                missing_chunk->id,
                missing_chunk->hash_str_short);
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
            DPRINTF(DEBUG_CMD_GET, "Don't have #%hu %s\n",
                    missing_chunk->id,
                    missing_chunk->hash_str_short);
            strcpy(missing_chunk->data_file, outputfile);
        }
        else
        {
            DPRINTF(DEBUG_CMD_GET, "Already have #%hu %s\n",
                    missing_chunk->id,
                    missing_chunk->hash_str_short);
            iter_drop_curr(missing_chunks_it);
        }
    }
    ITER_END(missing_chunks_it);
    if (missing_chunks->size == 0 || ongoing_jobs_exist())
    {
        if (missing_chunks->size == 0)
            printf("Already have everything");
        else
            printf("Already have an ongoing download");
        // Free missing chunks
        ITER_LOOP(missing_chunks_it, missing_chunks)
        {
            free(iter_drop_curr(missing_chunks_it));
        }
        ITER_END(missing_chunks_it);
    }
    else
    {
        get_chunks(missing_chunks, &config);
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
    
    FILE* master_chunk = fopen(config->chunk_file, "r");
    if (!master_chunk)
    {
        perror("peer_run could not open master chunk file");
        exit(-1);
    }
    if (fscanf(master_chunk, "File: %s\n", config->data_file) < 0)
    {
        perror("peer_run could not read master chunk file");
        fclose(master_chunk);
        exit(-1);
    }
    fclose(master_chunk);
    printf("data-file:     %s\n", config->data_file);
    
    owned_chunks = new_list();
    if (read_chunk_file(config->has_chunk_file, owned_chunks) < 0)
    {
        perror("peer_run could not read has_chunk_file");
        exit(-1);
    }
    
    ITER_LOOP(owned_chunks_it, owned_chunks)
    {
        chunk_t* owned_chunk = iter_get_item(owned_chunks_it);
        strcpy(owned_chunk->data_file, config->data_file);
    }
    ITER_END(owned_chunks_it);

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
    
    config->sock = sock;

    spiffy_init(config->identity, (struct sockaddr *) &myaddr, sizeof(myaddr));
    config->launch_time = get_time_msec();
    sprintf(config->cw_plot_file, "windowsize-peer-%i.txt", config->identity);
    // overwrites old file
    FILE* cw_plot = fopen(config->cw_plot_file, "w");
    fclose(cw_plot);

    while (1) {
        int nfds;
        FD_ZERO(&readfds);
        FD_SET(STDIN_FILENO, &readfds);
        FD_SET(sock, &readfds);
        struct timeval timeout = {0, 500 * 1000};
        
        nfds = select(sock+1, &readfds, NULL, NULL, &timeout);
//        printf(".");
//        fflush(stdout);

        if (nfds > 0) {
//            printf("\n");
//            fflush(stdout);
            
            if (FD_ISSET(sock, &readfds)) {
                process_inbound_udp(sock);
            }

            if (FD_ISSET(STDIN_FILENO, &readfds)) {
                process_user_input(STDIN_FILENO, userbuf, handle_user_input,
                                   "Currently unused");
            }
        }
        else
        {
            seeder_timeout(config);
            leecher_timeout(config);
        }
    }
}
