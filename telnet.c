/* telnet.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2006/02/23 17:58:29 $
 * $Revision: 1.2 $
 *
 * This module is the main part:
 *  - command line parsing
 *  - client loop
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
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h> 
#include <bios.h>

#include "tcp.h"
#include "version.h"
#include "vidio.h"
#include "vttio.h"
#include "keyio.h"
#include "keymap.h"
#include "config.h"
#include "telnet.h"
#include "common.h"

/* external functions */
SendFuncPtr SendPacket;
void ChrDelete(void);

/* external structures, variables */
extern unsigned short statusline;
extern unsigned columns;  /* Columns on logical terminal screen */
extern unsigned lines;    /* Lines on logical terminal screen */
extern unsigned short vidmode;

/* global variables */
Config GlobalConfig;		/* global configuration structure */
unsigned short Configuration = 0;	/* Configuration bits */

/* local variables */
struct vidmod{
 char *mode;
 unsigned short vidmode;
};
static struct vidmod modes[]={ {"80x25", 3},
                               {"80x60", 0x108},
                               {"132x25", 0x109},
                               {"132x50", 0x10b} };
static unsigned char Inbuf[1024];	/* buffer for incoming data */
static unsigned char Outbuf[1024];	/* buffer for outgoing data */
static unsigned char echo = 0;		/* is the echoing on? */
static char *RemoteHost = NULL;
static unsigned char *term;
static unsigned short RemotePort = 23;
static FILE *LogFile = NULL;

/*
 * Send Telnet packet
 */
void SendTelnetPacket(char *buff, unsigned short len)
{
   if(sock_write(&GlobalConfig.s, buff, len) != len)
        fatal("Sock write: %s", strerror(errno));
}

/*
 * Send Telnet command
 */
static void SendTC(unsigned char c1, unsigned char c2)
{
unsigned char buff[3];

   buff[0] = IAC;
   buff[1] = c1;
   buff[2] = c2;
   SendPacket(buff, 3);
}

/*
 * Initialize global structures
 */
static void Config_Init(void)
{
   memset(Outbuf, 0, sizeof(Outbuf));
   term = "xterm"; /* default is "xterm" */
   SendPacket = SendTelnetPacket;
   LogFile = NULL;
   GlobalConfig.brailab = NULL;
}

/*
 * Client loop. This runs until Telnet connection is terminated
 */
static short dosession(void)
{
unsigned short n;
unsigned short len;
unsigned char Command, Option, y, s;
unsigned char *ptr;
unsigned char sb[40];

   while(ConChk()){	/* examine STDIN */
	if(echo)	/* If we have remote echo, don't bother much */
	   DoKey();
	else{		/* else we have to buffer user input */
	   n = strlen(Outbuf);
	   y = getch();
	   if(!y){		 /* we have a special character here? */
                y = getch();
        	s = _bios_keybrd(_KEYBRD_SHIFTSTATUS) & 3; /* shift state */
		if(y == 0x2D)	 /* ALT-X ? */
		   fatal("Terminating session");
		else if(y == 0x49 && s){ /* shift+pgup */
                   SbkBack();
                   break;
                } else if(y == 0x51 && s){
                   SbkForward();
                   break;
                } else
		   break;
	   }
	   SbkSetPage(-1);
	   ConOut(y);	/* echo to screen */
	   switch(y){
		case 8: /* backspace */
		   if(n > 0)
			Outbuf[n-1] = 0;
		   ChrDelete();
		   break;

		case('\r'): /* return */
		   ConOut('\n');
		   strcat(Outbuf, "\n");
		   SendPacket(Outbuf, strlen(Outbuf));
		   memset(Outbuf, 0, strlen(Outbuf));
		   break;

		default:
		   strncat(Outbuf, &y, 1);
		   break;
	   } /* switch */
	} /* else */
   } /* while */

	if(!tcp_tick(&GlobalConfig.s)){ /* TCP wait */
	   puts("Connection closed");
           return(EXIT_TELNET);
        }

	if(!sock_dataready(&GlobalConfig.s))
	   return(0); /* Begin loop again if none */

        SbkSetPage(-1);

	len = sock_fastread(&GlobalConfig.s, Inbuf, 1024);

	for(ptr = Inbuf; len > 0; len--){
	   if(*ptr != IAC){ /* isn't it a Telnet command? */
		ConOut(*ptr);
		if(LogFile)
		   fputc(*ptr, LogFile);
                ptr++;
	   }
	   else{	/* It's a Telnet command */
		ptr++;
		Command = *ptr++;
		len--;
		if( Command == IAC ) /* double IAC means command terminated */
		   continue;
		Option = *ptr++;
		len--;

		switch(Option) {

		   case TELOPT_ECHO:
			switch(Command){
			   case WILL: /* server WILL echo. Do it */
				echo = 1;
				SendTC( DO, TELOPT_ECHO );
				break;

			   case WONT:
				echo = 0;
				SendTC( DONT, TELOPT_ECHO );
				break;

			   case DO: /* we won't echo no matter what */
			   case DONT:
				SendTC( WONT, TELOPT_ECHO );
				break;
			} /* switch */
                	break;

		   case TELOPT_SGA: /* suppress go ahead */
			if( Command == WONT )
			   SendTC( DONT, TELOPT_SGA );
			else if( Command == WILL){
			   SendTC( DO, TELOPT_SGA );
			   if(!echo)
				SendTC( DO, TELOPT_ECHO );
			}
			break;

		   case TELOPT_TTYPE:
			if( Command == DO ) /* we will send our terminal type */
			   SendTC( WILL, TELOPT_TTYPE );
			else if( Command == SB ){
			   /* find end of subnegotiation */
			   for(; *ptr != SE; ptr++, len--);
                           ptr++; len--;
			   SendTC(SB, TELOPT_TTYPE);
			   n = strlen(term);
			   sb[0] = '\0';
			   memcpy(sb + 1, term, n);
			   sb[n+1] = 0xFF;
			   sb[n+2] = SE;
			   SendPacket(sb, n + 3);
			} /* else if */
			break;

		   case TELOPT_NAWS: /* terminal window size */
			if( Command == DO ){
			   SendTC( WILL, TELOPT_NAWS );
                           SendTC( SB, TELOPT_NAWS);
                           sb[0] = 0;
                           sb[1] = columns;
                           sb[2] = 0;
                           sb[3] = lines - statusline;
                           sb[4] = IAC;
                           sb[5] = SE;
                           SendPacket(sb, 6);
                        }
			break;

		   default:
			switch(Command){

			   case WILL:
			   case WONT:
				SendTC( DONT, Option );
				break;

			   case DO:
			   case DONT:
				SendTC( WONT, Option );
				break;
			} /* switch */
			break;
		} /* switch */
	   } /* else */
	}/* for */

   return(0);

}

/*
 * Get command line arguments
 */
static void getargs(int argc, char *argv[])
{
unsigned short i, n;
char *s;
#if defined (__386__)
   char usage[]="Usage: tel386 [options] remotehost\n"
#else
   char usage[]="Usage: telnet [options] remotehost\n"
#endif
	    "Options:\n"
	    "-t <terminal type>                 - terminal type (default: xterm)\n"
	    "-p <port number>                   - remote port\n"
	    "-k <keymap file>                   - path to keymap file\n"
	    "-m <mode>                          - screen mode: 80x25 80x60 132x25 132x50\n"
	    "-l <log file>                      - log session to file\n"
	    "-b <COM[1234]>                     - Brailab PC adapter on COM[1234] port\n"
	    "-P                                 - use non privileged local port\n"
	    "-S                                 - disable status line\n"
	    "-n                                 - add CR if server sends only LF";

   for(i = 1; i < argc; ++i){
	s = argv[i];
	if(*s != '-') break;
	switch (*++s){
	   case '\0':
		fatal(usage);

	   case 't':
		if(*++s)
		   term = s;
		else if(++i < argc)
		   term = argv[i];
	    	else
		   fatal(usage);
		continue;

	   case 'm':
		if(*++s){
		   for(n = 0; n < 4; n++)
		      if(!strcmp(s, modes[n].mode)){
		         vidmode = modes[n].vidmode;
			 break;
                      }
		   if(!vidmode)
			fatal(usage);
		}
		else if(++i < argc){
		   for(n = 0; n < 4; n++)
		      if(!strcmp(argv[i], modes[n].mode)){
		         vidmode = modes[n].vidmode;
			 break;
                      }
		   if(!vidmode)
			fatal(usage);
		}
	    	else
		   fatal(usage);
		continue;

	   case 'p':
		if(*++s)
		   RemotePort = atoi(s);
		else if(++i < argc)
		   RemotePort = atoi(argv[i]);
		else
		   fatal(usage);
		continue;

	   case 'b':
		if(*++s){
		   strupr(s);
		   if(!strcmp(s, "COM1") ||
		      !strcmp(s, "COM2") ||
		      !strcmp(s, "COM3") ||
		      !strcmp(s, "COM4")){
			if((GlobalConfig.brailab = fopen(s,"w+b")) == NULL){
			   fatal("Cannot open COM port");
			}
		   }
		   else
			fatal(usage);
		}
		else if(++i < argc){
		   strupr(argv[i]);
		   if(!strcmp(argv[i], "COM1") ||
		      !strcmp(argv[i], "COM2") ||
		      !strcmp(argv[i], "COM3") ||
		      !strcmp(argv[i], "COM4")){
			if((GlobalConfig.brailab = fopen(argv[i],"w+b")) == NULL){
			   fatal("Cannot open COM port");
			}
		   }
		   else
			fatal(usage);
		}
		else
		   fatal(usage);
		continue;

	   case 'k':
		if(*++s)
		   keymap_init(s);
		else if(++i < argc)
		   keymap_init(argv[i]);
		else
		   fatal(usage);
		continue;

	   case 'l':
		if(*++s){
		   if((LogFile = fopen(s,"w+b")) == NULL)
			fatal("Cannot create log file");
		}
		else if(++i < argc){
		   if((LogFile = fopen(argv[i],"w+b")) == NULL)
			fatal("Cannot create log file");
		}
		else
		   fatal(usage);
		continue;

	   case 'P':
		Configuration |= NONPRIVILEGED_PORT;
		continue;

	   case 'S':
		statusline = 0;
		continue;

	   case 'n':
		Configuration |= NEWLINE;
		continue;

	   default:
		fatal(usage);
	} /* end switch */

   } /* end for */

   /* no_more_options */
   if(i + 1 > argc)
	fatal(usage);
   RemoteHost = argv[i++];
}

/*
 * Main program starts here
 */
int main(int argc, char **argv)
{
#if defined (__386__)
   printf("TELNET v%s. 386+ version\n", SSH_VERSION);
#else
   printf("TELNET v%s\n", SSH_VERSION);
#endif

   Config_Init();	/* Initialize global variables */
   getargs(argc, argv); /* Process command line */

   VESACheck();
   SetMode();
   VidParam();          /* Get proper screen size for PTY negotiation */


   TCPConnect(RemoteHost, RemotePort);      /* connect to server */

   sock_mode(&GlobalConfig.s, TCP_MODE_NAGLE );

   VidInit("user", RemoteHost);
   VTInit();

   while(EXIT_TELNET != dosession());	/* Loop until session end */

   VidUninit();

   sock_close(&GlobalConfig.s);	/* Close TCP socket */

   /* Close open files */
   if(GlobalConfig.brailab)
	fclose(GlobalConfig.brailab);
   if(LogFile)
	fclose(LogFile);

   return(0);
}
