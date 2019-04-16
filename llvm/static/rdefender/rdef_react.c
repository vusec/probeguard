#include <pthread.h>
#include <stdio.h>
#include <assert.h>
#include "rdef_common.h"
#include "rdefender.h"
#include <unistd.h>
#include "rdef_net.h"
#include "rdef_react.h"
#include "rdef_signal.h"

#define RDEF_MAX_PROCS          17
#define rdef_cmdsvr_conf() (&rdef_cmdsvr_conf_buff)
#define RDEF_CMD_STRS \
	"rdef_activate_defense", 	\
	"rdef_reset_defenses",		\
	NULL

// Define these so that we do not use pthread_cancel and pthread_join
// during closing. We only want one listener thread per process.
#define _UTIL_PTHREAD_CANCEL(C)		(0*C);
#define _UTIL_PTHREAD_JOIN(C, D)	(0*C);

#include <common/util/cmdsvr.h>
#include <stdlib.h>

static util_cmdsvr_conf_t rdef_cmdsvr_conf_buff;
//static rdef_endpoint_t rdef_parent = { _UTIL_CMDSVR_DEFAULT_DIR, _UTIL_CMDSVR_NAME_TO_FILE("rdef"), 0 };
static rdef_endpoint_t rdef_parent = { "/home/koustubha/repositories/rdef/apps/nginx-0.8.54/.tmp", _UTIL_CMDSVR_NAME_TO_FILE("rdef"), 0 };
#ifdef FOR_SPEC
rdef_endpoint_t rdef_uds_endpoint = { SPEC_TMP_DIR, _UTIL_CMDSVR_NAME_TO_FILE("rdef"), 0 };
#else
rdef_endpoint_t rdef_uds_endpoint = { "/home/koustubha/repositories/rdef/apps/nginx-0.8.54/.tmp", _UTIL_CMDSVR_NAME_TO_FILE("rdef"), 0 };
#endif
static pthread_mutex_t _switchboard_mutex;
extern uint64_t rdf_switchboard[32000];

void rdef_enable_defense(uint64_t llvm_id);

/* Command server functions. */

void rdef_is_valid_cmd(int cmd)
{
  assert(cmd >=0 && cmd < __NUM_RDEF_CMDS);
}

/* Handler that updates the switchboard accordingly */
util_cmdsvr_cb_ret_t rdef_cmdsvr_cb(util_cmdsvr_conf_t *conf)
{
  rdef_is_valid_cmd(conf->req.cmd);
  char *rest;
  uint64_t llvm_id;
  switch(conf->req.cmd) {
  	case RDEF_ACTIVATE_DEFENSE:
            llvm_id = strtoull(conf->req.buff, &rest, 10);
            rdef_enable_defense(llvm_id);
	    rdef_print_info("Defense enabled for function id: %lu\n", llvm_id);
            sprintf(conf->req.buff, "%s", "ACK");
	    conf->req.size = 3;
	    break;

        case RDEF_RESET_DEFENSES:
           for (uint64_t i=0; i < rdf_switchboard_size; i++) {
               rdf_switchboard[i] = 0;
           }

	   rdef_print_info("Defenses disabled for all functions.\n");
           sprintf(conf->req.buff, "%s", "ACK");
	   conf->req.size = 3;
	   break;

       default: 
           sprintf(conf->req.buff, "%s", "NIL");
	   conf->req.size = 3;
           break;
  }
  rdef_print_info("Acking with : %s\n", conf->req.buff);
  return UTIL_CMDSVR_CB_RET_ACK;
}

void rdef_enable_defense(uint64_t llvm_id)
{
  pthread_mutex_lock(&_switchboard_mutex);
  	rdf_switchboard[llvm_id] = 1;
  pthread_mutex_unlock(&_switchboard_mutex);
}

#if 0
// initializes endpoint details of parent which is the recovery server
static int rdef_identify_parent()
{
  pid_t p_pid = rdef_parent.id;
  rdef_print_debug("rdef_parent id: %d\n", rdef_parent.id);
  while(0 != p_pid)
  {
     if (1 == rdef_proc_alive(p_pid)) {
	if (p_pid != rdef_parent.id) {
		rdef_parent.id = p_pid;
	}
	break;
     } else {
	rdef_pidq_remove(p_pid);
     }
     p_pid = rdef_pidq_first();
  }
  if ( 0 == rdef_parent.id )
  {
     rdef_parent.id = getpid(); // I am the parent, because I am initializing this first.
     rdef_print_debug("First parent : %d\n", rdef_parent.id);
     rdef_pidq_append(rdef_parent.id);
  }
   rdef_parent.id;
}
#endif

void rdef_cmdsvr_init()
{
    static const char *rdef_cmd_strs[] = { RDEF_CMD_STRS };
    util_cmdsvr_conf_t *cmdsvr_conf = &rdef_cmdsvr_conf_buff;

#if 0
    rdef_print_info("Identifying parent \n");
    rdef_identify_parent();	// sets rdef_parent.id
    rdef_print_info("Parent is: %d\n", rdef_parent.id);
#endif

    //cmdsvr_conf->file = (char*) _UTIL_CMDSVR_NAME_TO_FILE("rdef");
    cmdsvr_conf->dir = (char *)rdef_uds_endpoint.dir;
    cmdsvr_conf->file = (char *)rdef_uds_endpoint.file;
    rdef_print_info("socket file: %s/%s\n", cmdsvr_conf->dir, cmdsvr_conf->file);
    util_cmdsvr_from_env(cmdsvr_conf);

    cmdsvr_conf->cb = rdef_cmdsvr_cb;
    cmdsvr_conf->id = getpid();
    cmdsvr_conf->req.cmd_strs = rdef_cmd_strs;
    cmdsvr_conf->req.max_size = 1000;
    cmdsvr_conf->max_threads_allowed = 1;
    rdef_print_info("Initializing cmdsvr... \n");
    util_cmdsvr_init(cmdsvr_conf);
    return;
}

static void rdef_cmdsvr_close()
{
    util_cmdsvr_close(rdef_cmdsvr_conf());
}

/* Event handlers */
void rdef_cmdsvr_atfork_child()
{
    rdf_pid = getpid();
    sprintf(rdef_log_filename, "%s.%d", "/tmp/rdef.log", rdf_pid);
    rdef_log_fptr = fopen(rdef_log_filename, "w+");
    rdef_print_info("forked child: %d\n", rdf_pid);
    util_cmdsvr_close_child(rdef_cmdsvr_conf());
    rdef_cmdsvr_init();
    if (RDEF_E_FAIL == rdef_net_init()) {
	 rdef_print_error("Net initialization failed. [pid:%d] \n", rdf_pid);
    }
    //rdef_register_detector();
}

void rdef_cmdsvr_atexit()
{
    rdef_print_info("exiting process: %d\n", getpid());
    rdef_cmdsvr_close();
}

void rdef_cmdsvr_atexec()
{
    rdef_cmdsvr_close();
}

void rdef_cmdsvr_atinit()
{
    rdef_print_info("Calling rdef_cmdsvr_init()\n");
    rdef_cmdsvr_init();
    if (RDEF_E_FAIL == rdef_net_init()) {
	 rdef_print_error("Net initialization failed. [pid:%d] \n", rdf_pid);
    }
    //pthread_atfork(NULL, NULL, rdef_cmdsvr_atfork_child);
}


/* Constructor. */
__attribute__((constructor)) void rdef_cmdsvr_constructor()
{
    sbrk(0); // initialize __curbrk
    rdef_log_fptr = fopen(rdef_log_filename, "w+");
    rdef_cmdsvr_atinit();
    atexit(&rdef_cmdsvr_atexit);
    rdef_register_detector();
    rdef_print_info("constructor called.\n");
}

__attribute__((destructor)) void rdef_destructor()
{
     if (NULL != rdef_log_fptr) {
	fflush(rdef_log_fptr);
	fclose(rdef_log_fptr);
     }
}

/* client side */
int rdef_send_to_parent(char *msg, int nbytes)
{
  assert(strlen(msg) >= nbytes);

  rdef_endpoint_t *parent = &rdef_parent;

  // Am I myself the parent (recovery helper)
  if (rdf_pid == parent->id)
  {
    rdef_print_info("Parent [ %d ] itself has crashed. Nothing much to do.\n", parent->id); 
    return RDEF_E_FAIL;
  }

  struct sockaddr_un remote_sa;
  size_t remote_sz;
  int fd, ret;

  fd = util_safeio_socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (fd != -1)
  {
    rdef_print_error("safe_socket failed\n");
    return RDEF_E_FAIL;
  }

  memset(&remote_sa, 0, sizeof(remote_sa));
  remote_sa.sun_family = AF_UNIX;
  snprintf(remote_sa.sun_path, UNIX_PATH_MAX, "%s/%s.%d", parent->dir,
        parent->file, parent->id);
  remote_sz = SUN_LEN(&remote_sa);

  ret = connect(fd, (struct sockaddr*)&remote_sa, remote_sz);
  if (ret == 0) {
	rdef_print_error("Connecting to parent failed.");  
	return RDEF_E_FAIL;
  }

  ret = send(fd, msg, nbytes, 0);
  if (ret == 0) {
	close(fd);
	rdef_print_error("Sending to parent failed.\n");
	return RDEF_E_FAIL;
  }
  
  // receive ACK
  char ackbuff[10];
  ret = recv(fd, ackbuff, 4, 0);
  if (ret == 0) {
	rdef_print_error("ACK not received from parent.\n");
	return RDEF_E_FAIL;
  }
  
  close(fd);
  return RDEF_E_OK; 
}

