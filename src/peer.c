/*
 * peer.c
 *
 * Skeleton for CMPU-375 programming project #2.
 *
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
#include "peer-proto.h"
#include "peer.h"


bt_config_t config;
LinkedList* owned_chunks;
int sock;


void peer_run(bt_config_t* config);
int read_chunk_file(char* chunk_file, LinkedList* chunk_list);


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
    bt_peer_t* peer = config.peers;
    bt_peer_t* found = NULL;
    while (peer)
    {
        if (!memcmp(&peer->addr.sin_addr, &addr->sin_addr, sizeof(addr->sin_addr))
            && !memcmp(&peer->addr.sin_port, &addr->sin_port, sizeof(addr->sin_port))
            && !memcmp(&peer->addr.sin_family, &addr->sin_family, sizeof(addr->sin_family)))
        {
            found = peer;
            break;
        }
        peer = peer->next;
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
        chunk_t* chunk = malloc(sizeof(chunk));
        char hash_str[SHA1_HASH_SIZE*2];
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
    char buf[MAX_PACKET_LEN];

    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, MAX_PACKET_LEN, 0, (struct sockaddr *) &from, &fromlen);

    printf("Incoming message from %s:%d\n%s\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf);
    
    handle_packet(buf, owned_chunks, &from, fromlen, sock);
}


void process_get(char* chunkfile, char* outputfile) {
    DPRINTF(DEBUG_GET, "Processing GET command\n");
    
    FILE* chunkFile;
    //id 2 bytes
    //blank space 1 byte
    //hash SHA1_HASH_SIZE*2
    //1 byte for NULL terminator
    char line[SHA1_HASH_SIZE*2 + 4];
    char delim[] = " ";

    chunkFile = fopen(chunkfile, "r");
    if (chunkFile == NULL) {
        perror("process_get could not open chunkfile");
    } else {
        //build a linked list of wanted chunks
        chunk_info* head = NULL;
        while (fgets(line, sizeof(line), chunkFile) != NULL) {
            chunk_info* chk = (chunk_info *) malloc(sizeof(chunk_info));;
            chk->id = (short) strtol(strtok(line, delim), NULL, 10);
            hex2binary(strtok(NULL, delim), SHA1_HASH_SIZE*2, chk->hash);
            chk->next = head;
            head = chk;
        }

        // Construct WHOHAS packets
        char* pack_buf = (char *) malloc(MAX_PACKET_LEN+1);
        memset(pack_buf, 0, MAX_PACKET_LEN+1);

        // Add all fields in header except for pack_len and num_chunks
        uint16_t magic = htons(3752);
        memcpy(pack_buf, &magic, 2);
        char version = 1;
        memcpy(pack_buf+2, &version, 1);
        char type = 0;
        memcpy(pack_buf+3, &type, 1);
        // Assume head_len
        uint16_t head_len = htons(16);
        memcpy(pack_buf+4, &head_len, 2);

        // Assume head_len
        uint16_t pack_len = 20;
        uint8_t num_chunks = 0;
        char* hash_pointer = pack_buf+20;
        while (head != NULL) {
            memcpy(hash_pointer, head->hash, SHA1_HASH_SIZE);
            hash_pointer += 20;
            pack_len += 20;
            num_chunks++;
            head = head->next;

            //if cannot fit in one packet
            if (hash_pointer >= (pack_buf + MAX_PACKET_LEN)) {
                //complete or modify header
                pack_len = htons(pack_len);
                memcpy(pack_buf+6, &pack_len, 2);
                memcpy(pack_buf+16, &num_chunks, 1);

                //send to all peers
                bt_peer_t* peer = config.peers;
                while (peer != NULL) {
                    if (peer->id == config.identity) // FIXME
                    {
                        sendto(sock, pack_buf, MAX_PACKET_LEN, 0,
                        (const struct sockaddr *) &(peer->addr),
                        sizeof(peer->addr));
                    }
                    peer = peer->next;
                }

                //start new packet
                pack_len = 20;
                num_chunks = 0;
                hash_pointer = pack_buf+20;
                memset(pack_buf+20, 0, MAX_PACKET_LEN+1);
            }
        }
        //all chunks exhausted
        //complete or modify header
        pack_len = htons(pack_len);
        memcpy(pack_buf+6, &pack_len, 2);
        memcpy(pack_buf+16, &num_chunks, 1);
        pack_len = ntohs(pack_len);
        //send to peers
        bt_peer_t* peer = config.peers;
        while (peer != NULL) {
            if (peer->id == config.identity) // FIXME
            {
                sendto(sock, pack_buf, pack_len, 0,
                       (const struct sockaddr *) &(peer->addr),
                       sizeof(peer->addr));
            }
            peer = peer->next;
        }
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
    
    owned_chunks = (LinkedList *) malloc(sizeof(LinkedList));
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
