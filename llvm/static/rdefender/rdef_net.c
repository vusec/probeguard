#include "rdef_common.h"
#include "rdef_net.h"
#include "rdef_react.h"
#include <sys/types.h>
#include <unistd.h>

static connection_t pt_dumper;
extern rdef_endpoint_t rdef_uds_endpoint;

void rdef_net_close(int fd)
{
  close(fd);
  return;
}

int rdef_net_connect(connection_t conxn)
{
  struct sockaddr_in server_addr;
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(RDEF_PT_DUMPER_PORT);
  if (!inet_aton(RDEF_PT_DUMPER_IP, &server_addr.sin_addr.s_addr))
  {
    rdef_print_error("%s - no such host.\n", RDEF_PT_DUMPER_IP);
    return RDEF_E_FAIL;
  }

  // Initiate connection
  rdef_print_info("Initiating connection with pt-dumper.\n");
  if ( 0 != connect(conxn.conxn_fd, (struct sockaddr *) &server_addr, sizeof(struct sockaddr_in)))
  {
    rdef_print_error("Unable to connect to the PT dumper server (%s:%d).\n", RDEF_PT_DUMPER_IP, 
                     RDEF_PT_DUMPER_PORT);
    rdef_net_close(conxn.conxn_fd);
    return RDEF_E_FAIL;
  }
  return RDEF_E_OK;
}

int rdef_send_uds_info(connection_t conxn)
{
  char cmd[500];

  rdf_pid = getpid();

  // Inform the PT server about the Unix domain socket used for switchboard control
  sprintf(cmd, "ctl init %s/%s.%d", rdef_uds_endpoint.dir, rdef_uds_endpoint.file, rdf_pid) ;
  rdef_print_info("cmdline: %s\n", cmd);
  if (RDEF_E_FAIL == rdef_send(cmd))
  {
        rdef_print_error("Failed initializing PT server with UDS server address\n");
        return RDEF_E_FAIL;
  }
  rdef_print_info("Sent UDS server address to PT server\n");
  if (RDEF_E_FAIL == rdef_receive_ack())
  {
        rdef_print_error("Failed to receive ACK from PT server.\n");
        return RDEF_E_FAIL;
  }
  rdef_print_info("rdef_send_uds_info() successful.\n");
  return RDEF_E_OK;
}

int rdef_net_init()
{
  rdef_print_info("Net initializing...\n");
  
  pt_dumper.conxn_fd = socket(AF_INET, SOCK_STREAM, 0);
  rdef_print_info("Socket initialized to talk to pt-dumper.\n");
  if (0 > pt_dumper.conxn_fd)
  {
    rdef_print_error("Failed creating client socket to %s(p:%d)\n", RDEF_PT_DUMPER_IP, RDEF_PT_DUMPER_PORT);
    rdef_net_close(pt_dumper.conxn_fd);
    return RDEF_E_FAIL;
  }

  // Set timeout for the socket
  struct timeval timeout;
  timeout.tv_sec = RDEF_NET_TIMEOUT;
  timeout.tv_usec = 0;
  setsockopt(pt_dumper.conxn_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));

  if (RDEF_E_FAIL == rdef_net_connect(pt_dumper))
	return RDEF_E_FAIL;

//#ifndef NO_UDS_INIT
//#if 0
  if (RDEF_E_FAIL == rdef_send_uds_info(pt_dumper)) {
	rdef_print_error("rdef_net_init() failed.\n");
	return RDEF_E_FAIL;
  }
//#endif

  rdef_print_info("communication initialized.\n");

  // Ask PT server to start tracing for this process.
  char cmd[50];
  rdf_pid = getpid();
  sprintf(cmd, "trace %d", rdf_pid);
  rdef_print_info("cmdline: %s\n", cmd);
  if (RDEF_E_FAIL == rdef_send(cmd))
  {
	rdef_print_error("Failed to ask PT server to start tracing for process: %d\n", rdf_pid);	return RDEF_E_FAIL;
  }
  rdef_print_info("Sent request to PT server to start tracing the process: %d\n", rdf_pid);
  if (RDEF_E_FAIL == rdef_receive_ack())
  {
	rdef_print_error("Failed to receive ACK from PT server.\n");
	return RDEF_E_FAIL;
  }
  rdef_print_info("Received ACK from PT server.\n");
  return RDEF_E_OK;
}

int rdef_send(const char *message)
{
  if (0 > pt_dumper.conxn_fd)
  {
    rdef_print_error("Connection error towards PT dumper server (%s:%d).\n", RDEF_PT_DUMPER_IP, RDEF_PT_DUMPER_PORT);
    return RDEF_E_FAIL;
  }

  size_t len = strlen(message);
  rdef_print_info("sending message of len: %zu\n", len);
  if (len > RDEF_MAX_STR_SIZE)
  {
    rdef_print_error("Cannot send more than fixed length of %d characters.\n", RDEF_MAX_STR_SIZE);
    return RDEF_E_FAIL;
  }

  int ret;
  ret = send(pt_dumper.conxn_fd, message, len, 0);
  if (0 > ret)
  {
    rdef_print_error("Sending message to PT server failed.\n");
    return RDEF_E_FAIL;
  }
  rdef_print_info("sent message.\n");
  return RDEF_E_OK;
}

int rdef_receive_ack()
{
  char buffer[RDEF_MAX_STR_SIZE];
  if (0 >= rdef_receive(buffer, 4))
	return RDEF_E_FAIL;
  buffer[3] = '\0'; // Expecting "ACK"
  rdef_print_info("received msg: %s\n", buffer);
  if (0 == strncmp("ACK", buffer, 3))
	return RDEF_E_OK;
  else
	return RDEF_E_FAIL;
}

int rdef_receive(char *buffer, size_t nbytes)
{
  size_t to_read = nbytes;

  assert(nbytes < RDEF_MAX_STR_SIZE && "Cannot read more than the set max buffer size");
  ssize_t ret = recv(pt_dumper.conxn_fd, buffer, to_read, 0);
  if (0 > ret)
  {
     rdef_print_error("Failed to receive message from PT server. %d[%s]\n", errno, strerror(errno));
  }
  else
  {
     rdef_print_info("Received message from PT server.\n");
  }
  return ret;
}
