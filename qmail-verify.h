#define DEFAULTQVPORT 11113
#define DEFAULTQVIP "127.0.0.1"
#define DEFAULTQVTIMEOUT 5

#define GETPW_USERLEN 32
/* Response length is status byte + username length */
#define QVRESPONSELEN (1+GETPW_USERLEN)

/* ADDR_NOK, ADDR_OK, ADDR_NOK_TEMP get ORed with POSx for possible debugging. */
#define ADDR_NOK_TEMP	0x02
#define ADDR_NOK	0x01
#define ADDR_OK		0x00
/* Treat a stat() error as 'valid address'; maybe not running with sufficient rights */
#define STATERR ADDR_OK
/* Which bits show OK / NOK: */
#define QVRESULTBITS 0x0f

#define QVPOS1	0x10
#define QVPOS2	0x20
#define QVPOS3	0x30
#define QVPOS4	0x40
#define QVPOS5	0x50
#define QVPOS6	0x60
#define QVPOS7	0x70
#define QVPOS8	0x80
#define QVPOS9	0x90
#define QVPOS10	0xa0
#define QVPOS11	0xb0
#define QVPOS12	0xc0
#define QVPOS13	0xd0
#define QVPOS14	0xe0
#define QVPOS15	0xf0
/* Which bits show QVPOSx: */
#define QVPOSBITS 0xf0
