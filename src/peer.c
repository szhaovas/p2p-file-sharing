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

#define MAXPACKSIZE 1500

bt_config_t config;
LinkedList* owned_chunks;
int sock;

void peer_run(bt_config_t *config);
int read_chunk_file(char* chunk_file, LinkedList* chunk_list);

typedef struct chunk_s {
    uint16_t id;
    uint8_t hash[SHA1_HASH_SIZE];
} chunk_t;

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


int read_chunk_file(char* chunk_file, LinkedList* chunk_list)
{
    FILE * fp;
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
        printf("chunk #%hu ", chunk->id);
        print_hex((char *) chunk->hash, SHA1_HASH_SIZE);
        printf("\n");
     }
    fclose(fp);
    return 0;
 }


bt_peer_t* find_peer_with_addr(bt_peer_t* peer, struct sockaddr_in* addr)
{
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
    uint8_t version, packet_type;
    uint16_t magic_no, header_len, packet_len;
    uint32_t seq_no, ack_no;
    char* payload;
    print_hex(buf, BUFLEN);
    if (parse_packet(buf, &packet_type, &header_len, &packet_len, &seq_no, &ack_no, &payload))
    {
        switch (packet_type)
        {
            case PTYPE_WHOHAS:
            {
                LinkedList* i_have = (LinkedList*) malloc(sizeof(LinkedList));
                init_list(i_have);
                uint8_t num_hash = 0;
                memcpy(&num_hash, payload, 1);
                payload += 4; // FIXME: use constant
                for (int i = 0; i < num_hash; i++)
                {
                    char hash[SHA1_HASH_SIZE];
                    memcpy(hash, payload, SHA1_HASH_SIZE);
                    printf("Looking for ");
                    print_hex(hash, SHA1_HASH_SIZE);
                    ITER_LOOP(it, owned_chunks)
                    {
                        chunk_t* chunk = (chunk_t *) iter_get_item(it);
                        printf("Comparing with ");
                        print_hex(chunk->hash, SHA1_HASH_SIZE);
                        if (!strncmp(hash, (char*) chunk->hash, SHA1_HASH_SIZE))
                        {
                            add_item(i_have, chunk);
                        }
                    }
                    ITER_END(it);
                }
                if (i_have->size)
                {
                    char reply_buf[BUFLEN];
                    memset(reply_buf, '\0', BUFLEN);
                    char* reply_payload, *reply_payload_start;
                    reply_payload = reply_buf + HEAD_LEN_NORMAL;
                    reply_payload_start = reply_payload;
                    uint8_t num_hash = i_have->size;
                    *reply_payload = num_hash;
                    reply_payload += 4; // FIXME: use a constant
                    ITER_LOOP(it, i_have)
                    {
                        chunk_t* chunk = (chunk_t *) iter_get_item(it);
                        memcpy(reply_payload, (char*) chunk->hash, SHA1_HASH_SIZE);
                        reply_payload += SHA1_HASH_SIZE;
                    }
                    ITER_END(it);
                    
                    make_packet(reply_buf,
                                PTYPE_IHAVE,
                                HEAD_LEN_NORMAL,
                                reply_payload-reply_buf,
                                FILED_N_A,
                                FILED_N_A,
                                reply_payload_start,
                                reply_payload-reply_payload_start);
                    
                    bt_peer_t* to_peer = find_peer_with_addr(config.peers, &from);
                    {
                        {
                        }
                    }
                    if (to_peer)
                    {
                        sendto(sock, reply_buf,
                               reply_payload-reply_buf,
                               0,
                               (const struct sockaddr *) &(to_peer->addr),
                               sizeof(to_peer->addr));
                    }
                    
                }
                break;
            }

            case PTYPE_IHAVE:
                // TODO
                break;

            case PTYPE_GET:
                // TODO
                break;

            case PTYPE_DATA:
                // TODO
                break;

            case PTYPE_ACK:
                // TODO
                break;

            case PTYPE_DENIED:
                // TODO
                break;

            default:
                // ERROR
                break;
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
        while (fgets(line, sizeof(line), chunkFile) != NULL) {
            chunk_info *chk = (chunk_info *) malloc(sizeof(chunk_info));;
            chk->id = (short) strtol(strtok(line, delim), NULL, 10);
            hex2binary(strtok(NULL, delim), SHA1_HASH_SIZE*2, chk->hash);
            chk->next = head;
            head = chk;
        }

        //construct and send WHOHAS packets
        char *pack_buf = (char *) malloc(MAXPACKSIZE+1);
        memset(pack_buf, 0, MAXPACKSIZE+1);

        //add all fields in header except for pack_len and num_chunks
        uint16_t magic = htons(3752);
        memcpy(pack_buf, &magic, 2);
        char version = 1;
        memcpy(pack_buf+2, &version, 1);
        char type = 0;
        memcpy(pack_buf+3, &type, 1);
        //assume head_len
        uint16_t head_len = htons(16);
        memcpy(pack_buf+4, &head_len, 2);

        //assume head_len
        uint16_t pack_len = 20;
        uint8_t num_chunks = 0;
        char *hash_pointer = pack_buf+20;
        while (head != NULL) {
            memcpy(hash_pointer, head->hash, SHA1_HASH_SIZE);
            hash_pointer += 20;
            pack_len += 20;
            num_chunks++;
            head = head->next;

            //if cannot fit in one packet
            if (hash_pointer >= (pack_buf + MAXPACKSIZE)) {
                //complete or modify header
                pack_len = htons(pack_len);
                memcpy(pack_buf+6, &pack_len, 2);
                memcpy(pack_buf+16, &num_chunks, 1);

                //send to all peers
                bt_peer_t *peer = config.peers;
                while (peer != NULL) {
                    if (peer->id == config.identity) // FIXME
                    {
                        sendto(sock, pack_buf, MAXPACKSIZE, 0,
                        (const struct sockaddr *) &(peer->addr),
                        sizeof(peer->addr));
                    }
                    peer = peer->next;
                }

                //start new packet
                pack_len = 20;
                num_chunks = 0;
                hash_pointer = pack_buf+20;
                memset(pack_buf, 0, MAXPACKSIZE+1);
            }
        }
        //all chunks exhausted
        //complete or modify header
        pack_len = htons(pack_len);
        memcpy(pack_buf+6, &pack_len, 2);
        memcpy(pack_buf+16, &num_chunks, 1);
        pack_len = ntohs(pack_len);
        //send to peers
        bt_peer_t *peer = config.peers;
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
    struct sockaddr_in myaddr;
    fd_set readfds;
    struct user_iobuf *userbuf;
    
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
