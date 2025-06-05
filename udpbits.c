#include "udpbits.h"
#include "ip.h"
#include "byte.h"
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>

int connect_udp(ip,port,errfn)
struct ip_address ip;
unsigned int port;
void (*errfn)();
{
  struct sockaddr_in sout;
  int fd;

  byte_zero(&sout,sizeof(sout));
  sout.sin_port = htons(port);
  sout.sin_family=AF_INET;
  byte_copy(&sout.sin_addr,sizeof(ip),&ip);
/*sout.sin_len = sizeof(sout); Commented out since optional & sin_len not defined on all OSes */
  if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) (*errfn)();
  if (connect(fd,(struct sockaddr *)&sout,sizeof(sout)) < 0) (*errfn)();
  return fd;
}
