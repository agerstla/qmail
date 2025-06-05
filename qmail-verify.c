/* qmail-verify: Based on Paul Jarc's realrcptto-2006.12.10 patch
 *		 this separates its functionality into a separate
 *		 program that can be invoked by an appropriately
 *		 modified qmail-smtpd. The assumption is that
 *		 qmail-verify will run as root or the UID that
 *		 owns mailboxes in a SingleUID setup, whilst
 *		 qmail-smtpd can continue to run as user qmaild.
 *
 *               Comments have been added to show which parts of
 *		 qmail-1.03 various sections of code relate to.
 *
 *		*This program is written to be used by
 *		 qmail-smtpd communicating with it using UDP.
 */ 

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <grp.h>
#include <pwd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "auto_break.h"
#include "auto_usera.h"
#include "auto_qmail.h"
#include "byte.h"
#include "case.h"
#include "cdb.h"
#include "constmap.h"
#include "error.h"
#include "fmt.h"
#include "open.h"
#include "str.h"
#include "stralloc.h"
#include "uint32.h"
#include "substdio.h"
#include "getln.h"
#include "env.h"
#include "ip.h"
#include "qmail-verify.h"
#include "errbits.h"
#include "scan.h"

#define enew()  { eout("qmail-verify: "); }
#define GETPW_USERLEN 32
#define MAXQUERYSIZE 900
/* 900 derived as max packet size from logic in addrparse() in qmail-smtpd.c */

stralloc envnoathost = {0};
stralloc percenthack = {0};
stralloc locals = {0};
stralloc vdoms = {0};

struct constmap mappercenthack;
struct constmap maplocals;
struct constmap mapvdoms;

char *quser;

stralloc response = {0};

char *local, *dash, *extension;
struct passwd *pw;

char ppid_s[FMT_ULONG];
char *remoteip;
char inbuf[MAXQUERYSIZE+1]; /* +1 for trailing \0 added after receipt */

void die_nomem()   { enew(); eout("Out of memory: exiting.\n"); eflush(); _exit(1); }
void die_control() { enew(); eout("Unable to read controls: exiting.\n"); eflush(); _exit(1); }
void die_cdb()     { enew(); eout("Unable to read cdb user database: exiting.\n"); eflush(); _exit(1); }
void die_sys()     { enew(); eout("Unable to read system user database: exiting.\n"); eflush(); _exit(1); }
void die_comms()   { enew(); eout("Misc. comms problem: exiting.\n"); eflush(); _exit(1); }
void die_inuse()   { enew(); eout("Port already in use: exiting.\n"); eflush(); _exit(1); }
void die_socket()  { enew(); eout("Error setting up socket: exiting.\n"); eflush(); _exit(1); }
void die_privs()   { enew(); eout("Unable to drop/restore privileges: exiting.\n"); eflush(); _exit(1); }

char *posstr(buf,status)
char *buf; int status;
{
int pos;

pos = status & QVPOSBITS;
if (pos==QVPOS1)  str_copy(buf,"1");
else if (pos==QVPOS2)  str_copy(buf,"2");
 else if (pos==QVPOS3)  str_copy(buf,"3");
  else if (pos==QVPOS4)  str_copy(buf,"4");
   else if (pos==QVPOS5)  str_copy(buf,"5");
    else if (pos==QVPOS6)  str_copy(buf,"6");
     else if (pos==QVPOS7)  str_copy(buf,"7");
      else if (pos==QVPOS8)  str_copy(buf,"8");
       else if (pos==QVPOS9)  str_copy(buf,"9");
        else if (pos==QVPOS10) str_copy(buf,"10");
         else if (pos==QVPOS11) str_copy(buf,"11");
          else if (pos==QVPOS12) str_copy(buf,"12");
           else if (pos==QVPOS13) str_copy(buf,"13");
            else if (pos==QVPOS14) str_copy(buf,"14");
             else if (pos==QVPOS15) str_copy(buf,"15");
              else str_copy(buf,"??");
return buf;
}

char posbuf[10]; /* Large enough for anything posstr() will put in it. */

int allowaddr(addr,ret)
char *addr;
int ret;
{
/*eout3("[DEBUG] Pos ",posstr(posbuf,ret),", ");*/
/*eout3("qmail-verify: ",addr," permitted.\n");*/
  enew(); eout4(addr," permitted for ",quser?quser:"UNKNOWN",".\n");
  eflush();
  return ret;
}

int denyaddr(addr,ret)
char *addr;
int ret;
{
/*eout3("[DEBUG] Pos ",posstr(posbuf,ret),", ");*/
/*eout3("qmail-verify: ",addr," denied.\n");*/
  enew(); eout2(addr," denied.\n");
  eflush();
  return ret;
}

int stat_error(path,staterror,ret)
char* path;
int staterror,ret;
{
/*eout3("[DEBUG] Pos ",posstr(posbuf,ret),", ");*/
/*eout5("qmail-verify: Unable to stat ",path,": ",error_str(staterror),".\n");*/
  enew(); eout5("Unable to stat ",path,": ",error_str(staterror),".\n");
  eflush();
  return ret;
}

int userext()	/* from qmail-getpw.c */
{
  char username[GETPW_USERLEN];
  struct stat st;

  extension = local + str_len(local);
  for (;;) {
    if (extension - local < sizeof(username))
      if (!*extension || (*extension == *auto_break)) {
	byte_copy(username,extension - local,local);
	username[extension - local] = 0;
	case_lowers(username);
	errno = 0;
	pw = getpwnam(username);
	if (errno == error_txtbsy) die_sys();
	if (pw)
	  if (pw->pw_uid)
	    if (stat(pw->pw_dir,&st) == 0) {
	      if (st.st_uid == pw->pw_uid) {
		dash = "";
		if (*extension) { ++extension; dash = "-"; }
		return 1;
	      }
	    }
	    else
	      if (error_temp(errno)) die_sys();
      }
    if (extension == local) return 0;
    --extension;
  }
}

int verify_aliasescdb(addr, fn)
char *addr;
char *fn;
{
  int fd;
  static stralloc key = {};
  uint32 dlen;
  int r;
  int at;

  fd = open_read(fn);
  if (fd == -1) die_cdb();
  if (!stralloc_copys(&key,":")) die_nomem();
  if (!stralloc_cats(&key,addr)) die_nomem();
  case_lowerb(key.s,key.len);

  r = cdb_seek(fd,key.s,key.len,&dlen);
  if (r == -1) die_cdb();
  if (r) { close(fd); return 1; }

  at = str_rchr(addr,'@');
  if (!addr[at]) { close(fd); return 0; }

  if (!stralloc_copys(&key,":")) die_nomem();
  if (!stralloc_cats(&key,addr + at)) nomem();
  case_lowerb(key.s,key.len);

  r = cdb_seek(fd,key.s,key.len,&dlen);
  if (r == -1) die_cdb();
  if (r) { close(fd); return 1; }

  if (!stralloc_copys(&key,":")) nomem();
  if (!stralloc_catb(&key,addr,at + 1)) nomem();
  case_lowerb(key.s,key.len);

  r = cdb_seek(fd,key.s,key.len,&dlen);
  if (r == -1) die_cdb();
  close(fd);
  if (r) return 1;

  return 0;
}

static int stat_as(uid, gid, path, sbuf)
const uid_t uid;
const gid_t gid;
const char * const path;
struct stat * const sbuf;
{
  static gid_t groups[NGROUPS_MAX + 1];
  int ngroups = 0;
  const gid_t saved_egid = getegid();
  const uid_t saved_euid = geteuid();
  int ret = -1;

  if (saved_euid == 0) {
    ngroups = getgroups(sizeof(groups) / sizeof(groups[0]), groups);
    if (ngroups < 0 ||
        setgroups(1, &gid) != 0 ||
        setegid(gid) != 0 ||
        seteuid(uid) != 0) {
      die_privs();
    }
  }

  ret = stat(path, sbuf);

  if (saved_euid == 0) {
    if (seteuid(saved_euid) != 0 ||
        setegid(saved_egid) != 0 ||
        setgroups(ngroups, groups) != 0) {
      die_privs();
    }
  }

  return ret;
}

int verifyaddr(addr)
char *addr;
{
  char *homedir;
  uid_t uid = -1;
  gid_t gid = -1;
  /* static since they get re-used on each call to verifyaddr(). Note
     that they don't need resetting since initial use is always with
     stralloc_copys() except wildchars (reset with ...len=0 below). */
  static stralloc localpart = {0};
  static stralloc lower = {0};
  static stralloc nughde = {0};
  static stralloc wildchars = {0};
  static stralloc safeext = {0};
  static stralloc qme = {0};
  unsigned int i,at;
  wildchars.len=0;

  /* qmail-send:rewrite */
  if (!stralloc_copys(&localpart,addr)) die_nomem();
  i = byte_rchr(localpart.s,localpart.len,'@');
  if (i == localpart.len) {
    if (!stralloc_cats(&localpart,"@")) die_nomem();
    if (!stralloc_cat(&localpart,&envnoathost)) die_nomem();
  }
  while (constmap(&mappercenthack,localpart.s + i + 1,localpart.len - i - 1)) {
    unsigned int j = byte_rchr(localpart.s,i,'%');
    if (j == i) break;
    localpart.len = i;
    i = j;
    localpart.s[i] = '@';
  }
  at = byte_rchr(localpart.s,localpart.len,'@');
  if (constmap(&maplocals,localpart.s + at + 1,localpart.len - at - 1)) {
    localpart.len = at;
    localpart.s[at] = '\0';
  } else {
    unsigned int xlen,newlen;
    char *x;
    for (i = 0;;++i) {
      if (i > localpart.len) return allowaddr(addr,ADDR_OK|QVPOS1);
      if (!i || (i == at + 1) || (i == localpart.len) ||
          ((i > at) && (localpart.s[i] == '.'))) {
        x = constmap(&mapvdoms,localpart.s + i,localpart.len - i);
        if (x) break;
      }
    }
    if (!*x) return allowaddr(addr,ADDR_OK|QVPOS2);
    xlen = str_len(x) + 1;  /* +1 for '-' */
    newlen = xlen + at + 1; /* +1 for \0 */
    if (xlen < 1 || newlen - 1 < xlen || newlen < 1 ||
        !stralloc_ready(&localpart,newlen))
      die_nomem();
    localpart.s[newlen - 1] = '\0';
    byte_copyr(localpart.s + xlen,at,localpart.s);
    localpart.s[xlen - 1] = '-';
    byte_copy(localpart.s,xlen - 1,x);
    localpart.len = newlen;
  }

  /* qmail-lspawn:nughde_get */
  {
    /* qmail-lspawn lines 83-128 */
    int r,fd,flagwild;

    if (!stralloc_copys(&lower,"!")) die_nomem();
    if (!stralloc_cats(&lower,localpart.s)) die_nomem();
    if (!stralloc_0(&lower)) die_nomem();
    case_lowerb(lower.s,lower.len);

    if (!stralloc_copys(&nughde,"")) die_nomem();

    fd = open_read("users/cdb");
    if (fd == -1) {
      if (errno != error_noent) die_cdb();
    }
    else
    { /* This section parses users/cdb file */
      uint32 dlen;

      r = cdb_seek(fd,"",0,&dlen);
      if (r != 1) die_cdb();
      if (!stralloc_ready(&wildchars,(unsigned int) dlen)) die_nomem();
      wildchars.len = dlen;
      if (cdb_bread(fd,wildchars.s,wildchars.len) == -1) die_cdb();

      i = lower.len;
      flagwild = 0;

      do { /* i > 0 */
        if (!flagwild || (i == 1) ||
            (byte_chr(wildchars.s,wildchars.len,lower.s[i - 1]) < wildchars.len))
        {
          r = cdb_seek(fd,lower.s,i,&dlen);
          if (r == -1) die_cdb();
          if (r == 1)
          {
            char *x;
            unsigned long u;
            if (!stralloc_ready(&nughde,(unsigned int) dlen)) die_nomem();
            nughde.len = dlen;
            if (cdb_bread(fd,nughde.s,nughde.len) == -1) die_cdb();
            if (flagwild)
              if (!stralloc_cats(&nughde,localpart.s + i - 1)) die_nomem();
            if (!stralloc_0(&nughde)) die_nomem();
            close(fd);
            /* maybe based on qmail-lspawn lines 190-214 */
            x=nughde.s;
            quser=nughde.s;
            /* skip username */
            x += byte_chr(x,nughde.s + nughde.len - x,'\0');
            if (x == nughde.s + nughde.len) return allowaddr(addr,ADDR_OK|QVPOS3);
            ++x;
            /* skip uid */
            scan_ulong(x,&u);
            uid = u;
            x += byte_chr(x,nughde.s + nughde.len - x,'\0');
            if (x == nughde.s + nughde.len) return allowaddr(addr,ADDR_OK|QVPOS4);
            ++x;
            /* skip gid */
            scan_ulong(x,&u);
            gid = u;
            x += byte_chr(x,nughde.s + nughde.len - x,'\0');
            if (x == nughde.s + nughde.len) return allowaddr(addr,ADDR_OK|QVPOS5);
            ++x;
            /* skip homedir */
            homedir=x;
            x += byte_chr(x,nughde.s + nughde.len - x,'\0');
            if (x == nughde.s + nughde.len) return allowaddr(addr,ADDR_OK|QVPOS6);
            ++x;
            /* skip dash */
            dash=x;
            x += byte_chr(x,nughde.s + nughde.len - x,'\0');
            if (x == nughde.s + nughde.len) return allowaddr(addr,ADDR_OK|QVPOS7);
            ++x;
            extension=x;
            goto got_nughde;
          }
        }
        /* qmail-lspawn lines 132-137 */
        --i;
        flagwild = 1;
      } while (i);
      close(fd);
    }
  }

  /* qmail-getpw lines 61-70 */
  local = localpart.s;
  quser = local;
  if (!userext()) {
    extension = local;
    dash = "-";
    pw = getpwnam(auto_usera);
    quser = auto_usera;
  }
  if (!pw) return denyaddr(addr,ADDR_NOK|QVPOS8);
  if (!stralloc_copys(&nughde,pw->pw_dir)) die_nomem();
  if (!stralloc_0(&nughde)) die_nomem();
  homedir=nughde.s;
  uid = pw->pw_uid;
  gid = pw->pw_gid;

  got_nughde:

  /* qmail-local:qmesearch, note qmeexists() becomes stralloc_0 + stat() */
  if (!*dash) return allowaddr(addr,ADDR_OK|QVPOS9);
  if (!stralloc_copys(&safeext,extension)) die_nomem();
  case_lowerb(safeext.s,safeext.len);
  for (i = 0;i < safeext.len;++i)
    if (safeext.s[i] == '.')
      safeext.s[i] = ':';
  {
    /* qmail-local lines 383-388 */
    struct stat st;
    int i;
    if (!stralloc_copys(&qme,homedir)) die_nomem();
    if (!stralloc_cats(&qme,"/.qmail")) die_nomem();
    if (!stralloc_cats(&qme,dash)) die_nomem();
    if (!stralloc_cat(&qme,&safeext)) die_nomem();
    if (!stralloc_0(&qme)) die_nomem();
/* e.g. homedir/.qmail-localpart */
    if (stat_as(uid,gid,qme.s,&st) == 0) return allowaddr(addr,ADDR_OK|QVPOS10);
    if (errno != error_noent) {
      return stat_error(qme.s,errno, STATERR|QVPOS11); /* Maybe not running as root so access denied */
    }
    /* qmail-local lines 398-404 */
    for (i = safeext.len;i >= 0;--i)
      if (!i || (safeext.s[i - 1] == '-')) {
        if (!stralloc_copys(&qme,homedir)) die_nomem();
        if (!stralloc_cats(&qme,"/.qmail")) die_nomem();
        if (!stralloc_cats(&qme,dash)) die_nomem();
        if (!stralloc_catb(&qme,safeext.s,i)) die_nomem();
        if (!stralloc_cats(&qme,"default")) die_nomem();
        if (!stralloc_0(&qme)) die_nomem();
/* e.g. homedir/.qmail-[xxx-]default */
        if (stat_as(uid,gid,qme.s,&st) == 0) {
	  /* if it's ~alias/.qmail-default, optionally check aliases.cdb */
          if (!i && (quser == auto_usera)) {
            char *s;
            if (s = env_get("VERIFY_FASTFORWARDCDB"))
              if (!verify_aliasescdb(addr, s))
                return denyaddr(addr,ADDR_NOK|QVPOS12);
          }
          return allowaddr(addr,ADDR_OK|QVPOS12);
        }
        if (errno != error_noent) /* Maybe not running as root so access denied */
          return stat_error(qme.s,errno,STATERR|QVPOS13);
      }
    return denyaddr(addr,ADDR_NOK|QVPOS14);
  }
  return denyaddr(addr,ADDR_NOK|QVPOS15); /* Not sure under what conditions this line triggered, if any */
}

int main()
{
  int n, sock;
  char result;
  socklen_t clientaddrlen;
  struct sockaddr_in sin, clientaddr;
  unsigned long lport; /* for scan_ulong, scan_uint not in qmail src */
  struct ip_address i;
  char *s;

  if (chdir(auto_qmail) == -1) die_control();
  if (control_init() == -1) die_control();

  if (control_rldef(&envnoathost,"control/envnoathost",1,"envnoathost") != 1)
    die_control();

  if (control_readfile(&locals,"control/locals",1) != 1) die_control();
  if (!constmap_init(&maplocals,locals.s,locals.len,0)) die_nomem();
  switch(control_readfile(&percenthack,"control/percenthack",0)) {
    case -1: die_control();
    case 0: if (!constmap_init(&mappercenthack,"",0,0)) die_nomem();
    case 1:
      if (!constmap_init(&mappercenthack,percenthack.s,percenthack.len,0))
        die_nomem();
  }
  switch(control_readfile(&vdoms,"control/virtualdomains",0)) {
    case -1: die_control();
    case 0: if (!constmap_init(&mapvdoms,"",0,1)) die_nomem();
    case 1: if (!constmap_init(&mapvdoms,vdoms.s,vdoms.len,1)) die_nomem();
  }
  if (!(s = env_get("LISTEN"))) s=DEFAULTQVIP;

  /* Re-read control files above on SIGHUP? */

  if (!(n=ip_scan(s,&i))) ip_scan(DEFAULTQVIP,&i);
  s+=n; if ((*s==':') && scan_ulong(s+1,&lport)) ; else lport=DEFAULTQVPORT;

  byte_zero(&sin, sizeof(sin));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(lport);
/*sin.sin_len = sizeof(sin); (optional, not defined on all systems) */
  byte_copy(&sin.sin_addr, sizeof(i),&i);

  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) die_socket();
  if (bind(sock, (struct sockaddr *) &sin, sizeof(sin))< 0) die_inuse();

  { char tmps1[IPFMT+1], tmps2[FMT_ULONG+1];
    tmps1[ip_fmt(tmps1,&i)]=0;
    tmps2[fmt_ulong(tmps2,ntohs(sin.sin_port))]=0;
    enew(); eout5("Listening on address: ",tmps1,", port ",tmps2,".\n"); eflush();
  }
  for (;;)
  {
    clientaddrlen=sizeof(clientaddr); /* Read & set by recvfrom */
    n = recvfrom(sock,inbuf, MAXQUERYSIZE, 0, (struct sockaddr *)&clientaddr, &clientaddrlen);
    if (n<=0) /* <0 for error, 0 for empty packet. */
    {
      enew(); eout("Error receiving packet.\n"); eflush();
      continue;
    }
    inbuf[n]='\0'; /* Turn it into a string ('\0' terminated) */

    quser = 0;
    result=(char)verifyaddr(inbuf);

    /* 'short' response packet - just the status byte - use the line below to replace 'long' version */
    /* if (sendto(sock,&result,1,0,(struct sockaddr *)&clientaddr,sizeof(clientaddr)) < 0) die_comms(); */

    /* 'long' response packet - status byte + controlling user (quser) */
    stralloc_ready(&response, 2);
    stralloc_copyb(&response, &result, 1);
    if (quser) stralloc_cats(&response, quser);
    if (response.len > QVRESPONSELEN) response.len = QVRESPONSELEN; /* Trim oversize response */
    if (sendto(sock,response.s,response.len,0,(struct sockaddr *)&clientaddr,sizeof(clientaddr)) < 0) die_comms();

  }
}
