#include "stralloc.h"
#include "ip.h"
#include "scan.h"

/* Returns pointer to first digit or ':' in string, or end-of-string
 * if neither found. Useful prior to scan_ip_port() if any options
 * may precede the IP / port in the string. */
char *find_digit_colon_eos(s)
char *s;
{
  while (*s != '\0')
  {
    if ( *s == ':') return s;
    if ((*s >= '0') && (*s <= '9')) return s;
    s++;
  }
  return s; /* end of string '\0' */
}

/* Takes a string specifying IP address and port, separated by ':'
 * If IP address and/or port are missing, supplied defaults are used.
 * 0, -1 returned on success, failure respectively. */
int scan_ip_port(s,defaultip,defaultport,ipp,portp)
char *s, *defaultip;
struct ip_address *ipp;
unsigned int defaultport, *portp;
{
  int n;
  char *sp;
  unsigned long port; /* long because of scan_ulong */

  if (!s) return -1; /* Can't scan a null string */
  sp = s;
  if (!(n=ip_scan(sp, ipp))) ip_scan(defaultip,ipp);
  sp += n; /* n is 0 if no IP found */
  if (!((*sp==':') && scan_ulong(sp+1,&port))) port=defaultport;
  *portp = (unsigned int)port;
  return 0;
}
