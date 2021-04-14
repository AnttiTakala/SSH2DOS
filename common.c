/* common.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2006/03/01 20:37:07 $
 * $Revision: 1.4 $
 *
 * Common functions
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
#include <stdarg.h>
#include <string.h>

#include "tcp.h"
#include "config.h"
#include "proxy.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

/* external functions, data */
extern Config GlobalConfig;		/* configuration variables */
extern unsigned short Configuration;    /* configuration variables */


/*
 * Fatal error handler
 */
void fatal(const char *fmt, ...)
{
va_list ap;
char buf[1024];

   va_start(ap, fmt);
   vsprintf(buf, fmt, ap);
   va_end(ap);
   puts(buf);
   printf("%s", sockerr(&GlobalConfig.s));
   sock_close(&GlobalConfig.s);
   exit(255);
}


/*
 * Try to connect, wait for established
 */
static void doconnect(unsigned long ip, unsigned short rp, unsigned short lp)
{
   if(!tcp_open(&GlobalConfig.s, lp, ip, rp, NULL))
      fatal("Unable to open TCP connection");

   /* Negotiate TCP connection */
   if(Configuration & VERBOSE_MODE)
      puts("Waiting for remote host to connect...");

   while(!sock_established(&GlobalConfig.s))
      if(!tcp_tick(&GlobalConfig.s))
         fatal("Remote host closed connection");

   return;
}


/*
 * Parse environment
 */
static void envparse(char *str, char **proxyhost, unsigned short *proxyport,
                     char **proxyuser, char **proxypass)
{
char *p;
short m, n;

   if((*proxyhost = (char *)malloc(128)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   if(strchr(str, '@')){ /* we have username and maybe password*/
      if((p = *proxyuser = (char *)malloc(32)) == NULL)
         fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
      for(n = 0; str[n] != '@' && str[n] != ':'; n++)
         p[n] = str[n];
      p[n] = 0;
      if(str[n++] == ':'){ /* we have password */
         if((p = *proxypass = (char *)malloc(32)) == NULL)
            fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
         for(m = 0; str[n] != '@'; m++, n++)
            p[m] = str[n];
         p[m] = 0;
         n++;
      }
      str += n;
   }
   if((p = strchr(str, ':')) != NULL){ /* we have port specified */
      *p++ = 0;
      *proxyport = atoi(p);
   }
   strcpy(*proxyhost, str);
}


/*
 * Connect to remote host via TCP
 */
void TCPConnect(char *remotehost, unsigned short remoteport)
{
char *env, method = NOPROXY;
char *proxyuser = NULL, *proxypass = NULL, *proxyhost = NULL;
unsigned short localport, proxyport = 0;
longword remoteip, proxyip;
short n;

   /* Allocate local port */
   localport = (rand() % 512) + 512;
   if(Configuration & NONPRIVILEGED_PORT)
      localport = localport + 512;

   sock_init(); /* Initialize socket */

   if((env = getenv("SOCKS_PROXY")) != NULL){ /* we have socks_proxy env.var */
      envparse(env, &proxyhost, &proxyport, &proxyuser, &proxypass);
      if(!proxyport)
         proxyport = SOCKS_PORT;
      method = SOCKS_PROXY;
   } else if((env = getenv("HTTP_PROXY")) != NULL){ /* we have http_proxy env.var */
      envparse(env, &proxyhost, &proxyport, &proxyuser, &proxypass);
      if(!proxyport)
         proxyport = HTTP_PORT;
      method = HTTP_PROXY;
   }

   if(proxyhost){   /* Resolve proxy */
      if((proxyip = resolve(proxyhost)) == 0)
         fatal("Unable to resolve `%s'", proxyhost);
      free(proxyhost);
   } else {   /* Resolve hostname */
      if((remoteip = resolve(remotehost)) == 0)
         fatal("Unable to resolve `%s'", remotehost);
   }

   switch(method){
      case NOPROXY:
         doconnect(remoteip, remoteport, localport);
         break;

      case SOCKS_PROXY:
         doconnect(proxyip, proxyport, localport);
         if(socks5_connect(remotehost, remoteport, proxyuser, proxypass))
            fatal("Failed to begin relaying via SOCKS");
         free(proxyuser);
         free(proxypass);
         break;

      case HTTP_PROXY:
         doconnect(proxyip, proxyport, localport);
         n = http_connect(remotehost, remoteport, proxyuser, proxypass);
         free(proxyuser);
         free(proxypass);
	 if(n)
            fatal("failed to begin relaying via HTTP");
	 break;
   }
}
