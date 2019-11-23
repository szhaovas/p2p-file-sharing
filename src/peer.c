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

#define MAXPACKSIZE 1500

bt_config_t config;

void peer_run(bt_config_t *config);

typedef struct chunk_i {
    short id;
    uint8_t hash[SHA1_HASH_SIZE];
    struct chunk_i *next;
} chunk_info;
typedef struct chunk_i chunk_info;

int main(int argc, char **argv) {
    
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


void process_inbound_udp(int sock) {
#define BUFLEN 1500
    struct sockaddr_in from;
    socklen_t fromlen;
    char buf[BUFLEN];
    
    fromlen = sizeof(from);
    spiffy_recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *) &from, &fromlen);
    
    printf("PROCESS_INBOUND_UDP SKELETON -- replace!\n"
           "Incoming message from %s:%d\n%s\n\n",
           inet_ntoa(from.sin_addr),
           ntohs(from.sin_port),
           buf);
}

void print_hex(char* str, int max)
{
    
    for (int i = 0; i < max; i++)
    {
        if (str[i] == '\0')
        {
            printf("00 ");
        }
        else
        {
            printf("%02x ", str[i] & 0xff);
        }
    }
}

void process_get(char *chunkfile, char *outputfile) {
    FILE *chunkFile;
    //id 2 bytes
    //blank space 1 byte
    //hash SHA1_HASH_SIZE*2
    //1 byte for NULL terminator
    char line[SHA1_HASH_SIZE*2 + 4];
    char delim[] = " ";
    
    chunkFile = fopen(chunkfile, "r");
    if (chunkFile == NULL) {
        perror("cannot open chunkfile");
    } else {
        //build a linked list of wanted chunks
        chunk_info *head = NULL;
        int num_chunks = 0;
        while (fgets(line, sizeof(line), chunkFile) != NULL) {
            chunk_info *chk = (chunk_info *) malloc(sizeof(chunk_info));;
            chk->id = (short) strtol(strtok(line, delim), NULL, 10);
            hex2binary(strtok(NULL, delim), SHA1_HASH_SIZE*2, chk->hash);
            chk->next = head;
            head = chk;
            num_chunks++;
        }
        
        //construct and send WHOHAS packets
        char *pack_buf = (char *) malloc(MAXPACKSIZE);
        
        //add all fields in header except for pack_len and n_chks
        uint16_t magic = htons(3752);
        memcpy(pack_buf, &magic, 2);
        char version = 1;
        memcpy(pack_buf+2, &version, 1);
        char type = 0;
        memcpy(pack_buf+3, &type, 1);
        uint16_t head_len = htons(16);
        memcpy(pack_buf+4, &head_len, 2);
        
        int sockfd;
        if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
            perror("socket creation failed");
            exit(EXIT_FAILURE);
        }
        struct sockaddr_in peeraddr;
        peeraddr.sin_family = AF_INET;
        
        uint16_t pack_len;
        uint8_t n_chks;
        char *hash_pointer = pack_buf+20;
        while (hash_pointer < (pack_buf + MAXPACKSIZE) &&
               head != NULL) {
            memcpy(hash_pointer, head->hash, SHA1_HASH_SIZE);
            hash_pointer += 20;
            num_chunks--;
            head = head->next;
            
            //if cannot fit in one packet
            if (hash_pointer >= (pack_buf + MAXPACKSIZE)) {
                //complete or modify header
                pack_len = htons(MAXPACKSIZE);
                memcpy(pack_buf+6, &pack_len, 2);
                n_chks = (MAXPACKSIZE - 20) / SHA1_HASH_SIZE;
                memcpy(pack_buf+16, &n_chks, 1);
                
                //send to all peers
                bt_peer_t *peer = config.peers;
                while (peer != NULL) {
                    peer = peer->next;
                }
                
                //start new packet
                hash_pointer = pack_buf+20;
            }
            else if (head == NULL) {
                //complete or modify header
                pack_len = num_chunks*SHA1_HASH_SIZE + 20;
                memcpy(pack_buf+6, &pack_len, 2);
                memcpy(pack_buf+16, &num_chunks, 1);
                
                //send to peers
                
            }
        }
    }
}

void handle_user_input(char *line, void *cbdata) {
    char chunkf[128], outf[128];
    
    bzero(chunkf, sizeof(chunkf));
    bzero(outf, sizeof(outf));
    
    if (sscanf(line, "GET %120s %120s", chunkf, outf)) {
        if (strlen(outf) > 0) {
            process_get(chunkf, outf);
        }
    }
}


void peer_run(bt_config_t *config) {
    int sock;
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;
    
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
    
    spiffy_init(config->identity, (struct sockaddr *)&myaddr, sizeof(myaddr));
    
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
