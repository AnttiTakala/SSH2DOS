#ifndef _TELNET_H
#define _TELNET_H

#define	IAC	255		       /* interpret as command */
#define	DONT	254		       /* you are not to use option */
#define	DO	253		       /* please, you use option */
#define	WONT	252		       /* I won't use option */
#define	WILL	251		       /* I will use option */
#define	SB	250		       /* interpret as subnegotiation */
#define BREAK   243
#define	SE	240		       /* end sub negotiation */

#define TELOPT_BINARY	0	       /* 8-bit data path */
#define TELOPT_ECHO	1	       /* echo */
#define	TELOPT_SGA	3	       /* suppress go ahead */
#define	TELOPT_NAMS	4	       /* approximate message size */
#define	TELOPT_STATUS	5	       /* give status */

#define	TELOPT_TTYPE	24	       /* terminal type */
#define	TELOPT_NAWS	31	       /* window size */
#define TELOPT_XDISPLOC	35	       /* X Display Location */
#define TELOPT_OLD_ENVIRON 36	       /* Old - Environment variables */
#define TELOPT_NEW_ENVIRON 39	       /* New - Environment variables */

#define EXIT_TELNET	1382

#define TSBUFSIZ 41

#endif
