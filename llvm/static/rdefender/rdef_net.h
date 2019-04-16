/***********************************
* Sender is the rdefender static library
* Receiver is the PT recorder

- TODO: Improvements:
- Receiving success or failure from PT dumper
- When to close the pt_dumper connection?
- Keep keeping the pt_dumper connection open all the time?
************************************/

#ifndef RDEF_NET_H
#define RDEF_NET_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "rdef_common.h"

#define RDEF_PT_DUMPER_PORT 0x2DEF
#define RDEF_PT_DUMPER_IP   "127.0.0.1"
#define RDEF_NET_TIMEOUT	30	// in seconds
#ifdef FOR_SPEC
#define SPEC_TMP_DIR		"/home/koustubha/repositories/rdef/apps/SPEC_CPU2006/.tmp"
#endif
int socket_fd;

typedef struct
{
  int conxn_fd;
} connection_t;

void rdef_net_close(int fd);
int rdef_net_init();
int rdef_send(const char *message);
int rdef_receive_ack();
int rdef_receive(char *buffer, size_t nbytes);

#endif
