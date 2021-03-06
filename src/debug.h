#ifndef _DEBUG_H_
#define _DEBUG_H_

#include <stdio.h>  /* for perror */
#include <sys/types.h>

#ifdef DEBUG
extern unsigned int debug;
#define DPRINTF(level, fmt, args...) \
        do { if (debug & (level)) fprintf(stderr, fmt , ##args ); } while(0)
#define DEBUG_PERROR(errmsg) \
        do { if (debug & DEBUG_ERRS) perror(errmsg); } while(0)
#else
#define DPRINTF(args...)
#define DEBUG_PERROR(args...)
#endif

/*
 * The format of this should be obvious.  Please add some explanatory
 * text if you add a debugging value.  This text will show up in
 * -d list.  This list is processed by debugparse.pl to create the
 * help file automatically.
 */
#define DEBUG_NONE              0x00    // DBTEXT:  No debugging
#define DEBUG_ERRS              0x01    // DBTEXT:  Verbose error reporting
#define DEBUG_INIT              0x02    // DBTEXT:  Debug initialization
#define DEBUG_SOCKETS           0x04    // DBTEXT:  Debug socket operations
#define DEBUG_SPIFFY            0x08    // DBTEXT:  Debug the spiffy sending code
#define DEBUG_LEECHER           0x10    // DBTEXT:  Debug leecher
#define DEBUG_LEECHER_RELIABLE  0x20    // DBTEXT:  Debug leecher reliability
#define DEBUG_LEECHER_ALL       0x30    // DBTEXT:  Debug leecher (all)
#define DEBUG_SEEDER            0x40    // DBTEXT:  Debug seeder
#define DEBUG_SEEDER_RELIABLE   0x80    // DBTEXT:  Debug seeder reliability
#define DEBUG_SEEDER_ALL        0xC0    // DBTEXT:  Debug seeder (all)
#define DEBUG_CMD_GET           0x100   // DBTEXT:  Debug GET commands
//#define DEBUG_PROCESSES         0x??    // DBTEXT:  Debug processes (fork/reap/etc)

#define DEBUG_ALL  0xffffffff

#ifdef __cplusplus
extern "C" {
#endif
  int set_debug(char *arg);  /* Returns 0 on success, -1 on failure */
#ifdef __cplusplus
}
#endif

void print_hex(int level, void* hex, int max);

#endif /* _DEBUG_H_ */
