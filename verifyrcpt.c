#include "verifyrcpt.h"
#include "qmail-verify.h"
#include "ip.h"
#include "stralloc.h"
#include "scan.h"
#include <sys/types.h>

static int verifyrcpt_initialised=0;
static int sockfd;

int flagdenyany=0; /* Can be interrogated in qmail-smtpd.c */

void verifyrcpt_init(svr,errfn) /* errfn must _exit */
char *svr; void (*errfn)();
{
  struct ip_address ip;
  unsigned int port;

  if (scan_ip_port(svr,DEFAULTQVIP,DEFAULTQVPORT,&ip,&port) == -1) (*errfn)();
  sockfd = connect_udp(ip,port,errfn);
  verifyrcpt_initialised=1;
}

int verifyrcpt(vip,r,defer,timeoutfn,errfn)
char *vip; stralloc *r; int defer; void (*timeoutfn)(),(*errfn)();
{
  char qvresponse[QVRESPONSELEN+1]; /* +1 for '\0' at end */
  int result,n;

  if (!vip) (*errfn)(); /* verifyrcpt should only be called if vip set */
  if (!verifyrcpt_initialised) verifyrcpt_init(vip,errfn);

  if (defer && flagdenyany) return ADDR_OK; /* Optional short circuit; "Controlling user" not discovered; remove this line if it's needed */
  n = query_skt(sockfd,r,qvresponse,QVRESPONSELEN,DEFAULTQVTIMEOUT,timeoutfn,errfn);
  if (n == 0) (*errfn)();
  result = qvresponse[0] & QVRESULTBITS;
  qvresponse[ ( (n > QVRESPONSELEN) ? QVRESPONSELEN : n) ] = '\0';
    /* "Controlling user" available in qvresponse+1 for logging etc. */

  if (result == ADDR_OK)
    return ADDR_OK;
  /* NOK: */
  flagdenyany = 1;
  return defer?ADDR_OK:ADDR_NOK; /* ADDR_OK if we're rejecting later */
}
