/* proxy.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.2 $
 *
 * This module is the proxy relaying part
 *
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */



#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tcp.h"
#include "config.h"
#include "common.h"
#include "proxy.h"
#include "macros.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

extern Config GlobalConfig;

/*
 * SOCKS5 user/pass authentication
 */
static short socks5_userauth(char *proxyuser, char *proxypass)
{
char buf[64];
short n;

   /* construct auth packet */
   n = strlen(proxyuser);
   buf[0] = 0x01;
   buf[1] = n;
   memcpy(buf + 2, proxyuser, n);
   n += 2;
   buf[n++] = strlen(proxypass);
   memcpy(buf + n, proxypass, strlen(proxypass));
   n += strlen(proxypass);
   if(sock_write(&GlobalConfig.s, buf, n) != n) /* send it */
      fatal("Socket write error. File: %s, line: %u", __FILE__, __LINE__);

   /* get and parse response */
   if(sock_read(&GlobalConfig.s, buf, 2) != 2)
      fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);
   
   if(buf[0] != 0x01 && buf[1] != 0x00){
      puts("socks5_userauth: bad version or user/pass");
      return(-1);
   }

   return(0);
}


/*
 * SOCKS5 connect
 */
short socks5_connect(char *remotehost, unsigned short remoteport,
                     char *proxyuser, char *proxypass)
{
short n;
char buf[64];
char *errors[] = { NULL,
                   "general SOCKS server failure\n",
                   "connection not allowed by ruleset\n",
                   "Network unreachable\n",
                   "Host unreachable\n",
                   "Connection refused\n",
                   "TTL expired\n",
                   "Command not supported\n",
                   "Address type not supported\n",
                   "Invalid address\n"};

   buf[0] = 0x05;
   if(proxyuser){ /* we have user/pass */
      buf[1] = 0x02; /* two auth methods */
      buf[2] = 0x00; /* try no auth */
      buf[3] = 0x02; /* try user/pass auth */
      n = 4;
   } else { /* only no auth method */
      buf[1] = 0x01;
      buf[2] = 0x00;
      n = 3;
   }
   if(sock_write(&GlobalConfig.s, buf, n) != n) /* send auth req */
      fatal("Socket write error. File: %s, line: %u", __FILE__, __LINE__);

   /* get and parse auth method response */
   if(sock_read(&GlobalConfig.s, buf, 2) != 2)
      fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);
   if(buf[0] != 0x05){
      puts("socks5: bad auth response version");
      return(-1);
   }
   switch(buf[1]){
        case 0: /* no auth */
           break;

        case 2: /* username/passwd */
           if(proxyuser){ /* we have user/pass */
              if(socks5_userauth(proxyuser, proxypass))
                 return(-1);
              else
                 break;
           } else {
              puts("socks5: no user/pass specified");
              return(-1);
           }

        default:
           puts("socks5: unsupported auth");
           return(-1);
   } /* switch */

   /* auth is done, request connection to remote host */
   buf[0] = 0x05;
   buf[1] = 0x01;
   buf[2] = 0x00;
   buf[3] = 0x03; /* ascii address type, not IP */
   n = strlen(remotehost);
   buf[4] = n;
   memcpy(buf + 5, remotehost, n);
   n += 5;
   PUT_16BIT_MSB_FIRST(buf + n, remoteport);
   n += 2;
   if(sock_write(&GlobalConfig.s, buf, n) != n) /* send req */
      fatal("Socket write error. File: %s, line: %u", __FILE__, __LINE__);

   /* get and parse response */
   if(sock_read(&GlobalConfig.s, buf, 5) != 5) /* this is enough to determine full length */
      fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);
   if(buf[0] != 0x05){
      puts("socks5: bad connection response version");
      return(-1);
   }
   if(buf[1]){
      printf("SOCKS5 error: ");
      if(buf[1] > 0x0A)
         printf("unknown error");
      else
         printf(errors[(short)buf[1]]);
      return(-1);
   } /* if */

   switch (buf[3]) {
      case 1: /* IP address */
         if(sock_read(&GlobalConfig.s, buf, 5) != 5) /* read rest */
            fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);
         break;

      case 3: /* domainname */
         if(sock_read(&GlobalConfig.s, buf, buf[4] + 2) != buf[4] + 2) /* read rest */
            fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);
         break;

        default:
            fatal("Bad SOCKS5 connection response");
   }
   return(0);
}

/*------------------------------- HTTP part -------------------------------*/


/*
 * Base64 encoding
 */
static char *b64_string(const char *str)
{
const char *base64_table =
"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *buf;
unsigned char *src;
char *dst;
int bits, data, src_len, dst_len;

   /* make base64 string */
   src_len = strlen(str);
   dst_len = (src_len+2)/3*4;
   if((buf = (char *)malloc(dst_len+1)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   bits = data = 0;
   src = (unsigned char *)str;
   dst = (unsigned char *)buf;
   while ( dst_len-- ) {
      if ( bits < 6 ) {
         data = (data << 8) | *src;
	 bits += 8;
	 if ( *src != 0 )
	    src++;
      }
      *dst++ = base64_table[0x3F & (data >> (bits-6))];
      bits -= 6;
   }
   *dst = '\0';
   /* fix-up tail padding */
   switch ( src_len%3 ) {
   case 1:
      *--dst = '=';
   case 2:
      *--dst = '=';
   }
   return buf;
}


/*
 * HTTP basic authentication
 */
static short http_auth(char *proxyuser, char *proxypass)
{
char *p, *c;
short len, ret;
    
   len = strlen(proxyuser) + strlen(proxypass) + 1;
   if((p = (char *)malloc(len + 1)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   sprintf(p, "%s:%s", proxyuser, proxypass);
   c = b64_string(p);
   ret = sock_printf(&GlobalConfig.s, "Proxy-Authorization: Basic %s\r\n", c);
   free(c);
   free(p);
    
   return ret;
}



/*
 * HTTP connect
 */
short http_connect(char *remotehost, unsigned short remoteport,
                   char *proxyuser, char *proxypass)
{
char buf[1024];
short result, n;

   if(sock_printf(&GlobalConfig.s,"CONNECT %s:%d HTTP/1.0\r\n", remotehost, remoteport) < 0)
      return -1;
   if(proxyuser)
      if(http_auth(proxyuser, proxypass) < 0)
         return -1;
   if(sock_puts(&GlobalConfig.s, "\r\n") < 0)
      return -1;

   /* get response */
   n = -1;
   do{
      n++;
      buf[n] = sock_getc(&GlobalConfig.s);
   } while(buf[n] != '\n');
   /* check status */
   result = atoi(strchr(buf,' '));
   if(result != 200)
      return -1;

   /* skip to end of response header */
   do{
      n = -1;
      do{
         n++;
         buf[n] = sock_getc(&GlobalConfig.s);
      } while(buf[n] != '\n');
   }while(buf[1] != '\n');

   return 0;
}
