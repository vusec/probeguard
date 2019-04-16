#ifndef RDEF_REACT_H
#define RDEF_REACT_H
#include <sys/types.h>

typedef enum rdef_cmd_e {
   RDEF_ACTIVATE_DEFENSE,
   RDEF_RESET_DEFENSES,
  __NUM_RDEF_CMDS
} rdef_cmd_t;

typedef struct {
  char *dir;
  char *file;
  int id;
} rdef_endpoint_t;

void rdef_cmdsvr_init();
int rdef_send_to_parent(char *msg, int nbytes);

#endif
