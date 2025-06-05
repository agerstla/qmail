#include "sockbits.h"
#include "stralloc.h"
#include <sys/types.h>
#include <sys/socket.h>
#include "error.h"

int query_skt(fd,queryp,responsep,maxresponsesize,timeout,timeoutfn,errfn)
int fd;
stralloc *queryp;
char *responsep;
int maxresponsesize, timeout;
void (*errfn)(), (*timeoutfn)();
{
  fd_set rfs;
  struct timeval tv;
  int nbytes;
  int r=0;

  if (write(fd,queryp->s,queryp->len) < 0) (*errfn)();
  tv.tv_sec=timeout; tv.tv_usec=0;
  FD_ZERO(&rfs); FD_SET(fd,&rfs);
  if ((r=select(fd+1,&rfs,(fd_set *) 0,(fd_set *) 0,&tv)) <= 0) /* 0 timeout or -1 error */
  {
    if ((r == 0) && (errno == error_timeout)) (*timeoutfn)();
    else (*errfn)();
    return r; /* if timeoutfn() / errfn() doesn't _exit() */
  }
  nbytes = read(fd,responsep,maxresponsesize);
  if (nbytes < 0) (*errfn)();
  return (nbytes); /* including 0 = no output */
}
