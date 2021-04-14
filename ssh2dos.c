/* ssh2dos.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:41 $
 * $Revision: 1.8 $
 *
 * This module is the main part:
 *  - command line parsing
 *  - client loop
 *  - running remote command or interactive session
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
#include <conio.h>
#include <string.h>
#include <time.h>
#include <dos.h>
#include <io.h>

#include "tcp.h"
#include "ssh.h"
#include "transprt.h"
#include "version.h"
#include "channel.h"
#include "config.h"
#include "common.h"
#include "negotiat.h"
#include "vidio.h"
#include "vttio.h"
#include "keyio.h"
#include "keymap.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

/* external functions */
SendFuncPtr SendPacket;

/* external structures, variables */
extern Packet pktin;	/* incoming SSH2 packet */
extern unsigned short statusline;
extern unsigned columns;  /* Columns on logical terminal screen */
extern unsigned lines;    /* Lines on logical terminal screen */
extern unsigned short vidmode;
extern char *protocolerror;

/* global variables */
Config GlobalConfig;		/* global configuration structure */
unsigned short Configuration;	/* Configuration bits */

/* local static variables */
struct vidmod{
 char *mode;
 unsigned short vidmode;
};
static struct vidmod modes[]={ {"80x25", 3},
                               {"80x60", 0x108},
                               {"132x25", 0x109},
                               {"132x50", 0x10b} };
static char *command = NULL;
static short tty = 0;
static char *RemoteHost = NULL;
static char *UserName = NULL;
static char *PassWord = NULL;
static char *KeyFile = NULL;
static char *term;
static unsigned short RemotePort = SSH_PORT;
static unsigned short Keepalives = 0;
static FILE *LogFile = NULL;

volatile int timer = 0;       /* increased by timer interrupt */
void (__interrupt __far *oldhandler)(); /* for old timer interrupt */

void __interrupt __far keepalive(void){
  timer++;
  _chain_intr(oldhandler);
}

/*
 * Initialize global variables
 */
static void Config_Init(void)
{
   term = "xterm"; /* default is "xterm" */
   SendPacket = SSH2_Channel_Send;
   GlobalConfig.debugfile = NULL;
   GlobalConfig.brailab = NULL;
   Configuration = 0;
   Configuration += DHGROUP;
}

/*
 * Allocate a pseudo terminal
 */
static void SSH2_Request_Pty(char *termtype)
{
   if(Configuration & VERBOSE_MODE)
        puts("Requesting PTY");
   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_REQUEST);
   SSH_putstring("pty-req");
   SSH_putbool(1);
   SSH_putstring(termtype);
   SSH_putuint32(columns);
   SSH_putuint32(lines - statusline);
   SSH_putuint32(0);
   SSH_putuint32(0);
   SSH_putstring("\0");
   SSH_pkt_send();

   SSH2_Channel_Read(SSH_MSG_CHANNEL_SUCCESS);
}

/*
 * Start interactive shell or run command
 */
static void SSH2_Start_Shell_Or_Command(void)
{
   if(command != NULL && command[0] != '\0') {
	if(Configuration & VERBOSE_MODE)
           puts("Running command");
	SSH2_Channel_PktInit(SSH_MSG_CHANNEL_REQUEST);
        SSH_putstring("exec");
        SSH_putbool(1);
        SSH_putstring(command);
	free(command);
   } else {
	if(Configuration & VERBOSE_MODE)
           puts("Running shell");
	SSH2_Channel_PktInit(SSH_MSG_CHANNEL_REQUEST);
        SSH_putstring("shell");
        SSH_putbool(1);
   }
   SSH_pkt_send();

   SSH2_Channel_Read(SSH_MSG_CHANNEL_SUCCESS);

}

/*
 * Client loop. This runs when the user successfully logged in,
 * until SSH connection is terminated
 */
static short dosession(void)
{
char *str;
unsigned long len;
unsigned short i;

   do{
        /* send keepalive SSH_MSG_IGNORE packet if configured */
        if( timer > Keepalives ){
	   SSH_pkt_init(SSH_MSG_IGNORE);
	   SSH_putstring("keepalive");
	   SSH_pkt_send();
	   timer = 0;
        } /* if */

        if(!tcp_tick(&GlobalConfig.s)){ /* TCP wait */
           puts("Remote host closed connection");
           return(EXIT_SSH);
        }
        while(ConChk()) /* examine STDIN */
	   DoKey();
   } while(!sock_dataready(&GlobalConfig.s));

   SbkSetPage(-1);

   SSH2_Channel_Read(0); /* uncrypt and get valuable data */

   switch(pktin.type){
        case SSH_MSG_CHANNEL_EXTENDED_DATA:
                pktin.ptr += 4;
        case SSH_MSG_CHANNEL_DATA:          /* we got data to display */
        	SSH_getstring(&str, &len); /* get and display data */
        	for (i = 0; i < len; i++){
                   if(tty)
                        ConOut(str[i]);
        	   else
                        putchar(str[i]);
        	}
        	if(LogFile)
        	   fwrite(str, 1, len, LogFile);
                break;

        case SSH_MSG_IGNORE:
		break;

	case SSH_MSG_CHANNEL_CLOSE:   /* channel is closed */
		SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "");
                return(EXIT_SSH);

   } /* switch */
   return(0);

}

/*
 * Get command line arguments
 */
static void getargs(int argc, char *argv[])
{
unsigned short n, i, j, len;
char *s;
#if defined (__386__)
   char usage[]="Usage: ssh2d386 [options] username remotehost [command [args]]\n"
#else
   char usage[]="Usage: ssh2dos [options] username remotehost [command [args]]\n"
#endif
	    "Options:\n"
	    "-i <identity file>                 - key file for public key authentication\n"
	    "-t <terminal type>                 - terminal type (default: xterm)\n"
	    "-p <port number>                   - remote port\n"
	    "-k <keymap file>                   - path to keymap file\n"
            "-m <mode>                          - screen mode: 80x25 80x60 132x25 132x50\n"
	    "-s <password>                      - remote password\n"
	    "-l <log file>                      - log session to file\n"
	    "-a <minutes>                       - time between keepalive packets\n"
	    "-b <COM[1234]>                     - Brailab PC adapter on COM[1234] port\n"
	    "-g                                 - use DH group1 key exchange\n"
	    "-P                                 - don't allocate a privileged port\n"
	    "-C                                 - enable compression\n"
	    "-S                                 - disable status line\n"
            "-B                                 - use BIOS calls for video output\n"
            "-V                                 - disable VESA BIOS\n"
	    "-n                                 - add CR if server sends only LF\n"
	    "-d                                 - save SSH packets to debug.pkt\n"
	    "-v                                 - verbose output";

   for (i = 1; i < argc; ++i){
	s = argv[i];
	if(*s != '-')
           break;
	switch (*++s){
	   case '\0':
		fatal(usage);

	   case 'i':
		if(*++s)
		   KeyFile = s;
		else if(++i < argc)
		   KeyFile = argv[i];
		else
		   fatal(usage);
		continue;

	   case 's':
		if(*++s)
		   PassWord = strdup(s);
		else if(++i < argc)
		   PassWord = strdup(argv[i]);
		else
		   fatal(usage);
		PassWord[MAX_PASSWORD_LENGTH - 1] = '\0';
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

	   case 'a':
		if(*++s)
		   Keepalives = atoi(s);
		else if(++i < argc)
		   Keepalives = atoi(argv[i]);
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

	   case 'g':
		Configuration -= DHGROUP;
		continue;

	   case 'P':
		Configuration += NONPRIVILEGED_PORT;
		continue;

	   case 'S':
		statusline = 0;
		continue;

	   case 'C':
		Configuration += COMPRESSION_REQUESTED;
		continue;

           case 'B':
                Configuration += BIOS;
                continue;

           case 'V':
                Configuration += NOVESA;
                continue;

	   case 'n':
		Configuration += NEWLINE;
		continue;

	   case 'd':
		if((GlobalConfig.debugfile = fopen("debug.pkt","w+")) == NULL)
		   fatal("Cannot create debug file");
		else
		   fputs("\n-------------------\n",GlobalConfig.debugfile);
		continue;

	   case 'v':
		Configuration += VERBOSE_MODE;
		continue;

	   default:
		fatal(usage);
	} /* end switch */

   } /* end for */

   /* no_more_options */
   if(i + 2 > argc)
        fatal(usage);
   UserName = argv[i++];
   RemoteHost = argv[i++];
   if(i >= argc)			/* command args? */
	return;
   /* collect remaining arguments and make a command line of them */
   for(len = 0, j = i; j < argc; j++)
	len += strlen(argv[j]) + 1;	/* 1 for the separating space */
   if((command = (char *)malloc(len)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   for(*command = '\0', j = i; j < argc; j++){
	strcat(command, argv[j]);	/* inefficient, but no big deal */
	if(j < argc - 1)		/* last argument? */
            strcat(command, " ");
   }
}

/*
 * Main program starts here
 */
int main(int argc, char **argv)
{
#if defined (__386__)
   printf("SSH2DOS v%s. 386+ version\n", SSH_VERSION);
#else
   printf("SSH2DOS v%s\n", SSH_VERSION);
#endif

   Config_Init();	/* Initialize global variables */
   srand(time(NULL));	/* Initialize random number generator */

   getargs(argc, argv); /* Process command line */

   VESACheck();
   SetMode();
   VidParam();          /* Get proper screen size for PTY negotiation */

   TCPConnect(RemoteHost, RemotePort);	/* Connect to server */

   SSH_Connect(UserName, PassWord, KeyFile); /* Start SSH negotiation */

   /* Request a pseudo terminal */
   if(isatty(fileno(stdout)))
	tty = 1;
   SSH2_Request_Pty(term);

   /* Start an interactive shell or run specified command */
   SSH2_Start_Shell_Or_Command();

   tcp_cbreak(1);	/* No Break checking */

   VidInit(UserName, RemoteHost);
   VTInit();

   if(Keepalives){	/* install keepalive timer */
	Keepalives = Keepalives * 18 * 60; /* correct keepalives value */
        oldhandler = _dos_getvect(0x1C);
        _dos_setvect(0x1C, keepalive);
   } /* if */

   while(EXIT_SSH != dosession());	/* Loop until session end */

   free(pktin.body);

   VidUninit();
   keymap_uninit();

   if(Configuration & COMPRESSION_ENABLED)
	Disable_Compression();

   if(Keepalives)
        _dos_setvect(0x1C, oldhandler);

   sock_close(&GlobalConfig.s); /* Close TCP socket */

   tcp_cbreak(0x10);	/* Break checking on */

   /* Close open files */
   if(GlobalConfig.brailab)
	fclose(GlobalConfig.brailab);
   if(GlobalConfig.debugfile)
	fclose(GlobalConfig.debugfile);
   if(LogFile)
	fclose(LogFile);

   return(0);
}
