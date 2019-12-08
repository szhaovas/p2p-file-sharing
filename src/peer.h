//
//  peer.h
//

#ifndef peer_h
#define peer_h


#include "sha.h"


/* Chunk struct */
typedef struct _chunk_t {
    uint16_t id;
    uint8_t hash[SHA1_HASH_SIZE];
    char hash_str[SHA1_HASH_STR_SIZE+1];
    char hash_str_short[SHA1_HASH_STR_SIZE+1];
    char data_file[BT_FILENAME_LEN];
} chunk_t;


/* Public functions */
void get_short_hash_str(const char* hash_str, char* hash_str_short);
void print_short_hash_str(int level, uint8_t* hash);
void print_chunks(int level, LinkedList* chunks);



#endif /* peer_h */
