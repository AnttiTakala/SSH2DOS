/* negotiat.c       Copyright (c) 2000-2005 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.5 $
 *
 * This module is the SSH negotiation part:
 *  - open TCP connection
 *  - protocol version check
 *  - initiate key exchange (transport layer)
 *  - initiate user authorization (authentication layer)
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
#include "auth.h"
#include "config.h"
#include "common.h"
#include "channel.h"
#include "sshsha.h"
#include "ssh.h"
#include "transprt.h"
#include "version.h"

/* external functions, data */
extern Config GlobalConfig;		/* configuration variables */
extern unsigned short Configuration;	/* configuration bitfields */
extern char *RemoteClosed;
extern char *ConnectionClosed;

/* global variables */
SHA_State exhashbase;

/*
 * SSH version string exchange: get server's SSH protocol
 * version, examine it, and send ours if it seems that we
 * can communicate
 */
static short SSH_Exchange_Identification(void)
{
char localstr[256], remotestr[256];
unsigned short remote_major, remote_minor;
int i;

   if(Configuration & VERBOSE_MODE)
        puts("Identification Exchange");

   /* Read other side's version identification. */
   do{
	if(!(i = sock_gets(&GlobalConfig.s, remotestr, sizeof(remotestr)))){
	   fatal("Cannot read remote identification string");
	}
   } while(strncmp(remotestr, "SSH-", 4)); /* ignore other lines */

   if(sscanf(remotestr, "SSH-%hu.%hu-", &remote_major, &remote_minor) != 2){
	SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Bad remote protocol version identification");
	return(1);
   }

   remotestr[i] = 0;
   remotestr[strcspn(remotestr, "\r\n")] = 0; /* cut \r\n if exists */

   if(Configuration & VERBOSE_MODE)
        printf("Remote version: %s\r\n",remotestr);

   sprintf(localstr, "SSH-%d.%d-SSHDOS_%s\r\n", PROTOCOL_MAJOR, PROTOCOL_MINOR, SSH_VERSION);
   if(Configuration & VERBOSE_MODE)
        printf("Local version: %s", localstr);

   if(remote_major < 2 && remote_minor != 99){
	SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED, "Unsupported remote protocol version");
	return(1);
   }

   if(sock_write(&GlobalConfig.s, localstr, strlen(localstr)) != strlen(localstr))
	fatal("Socket write error. File: %s, line: %u", __FILE__, __LINE__);

   /*
    * We must hash the version strings for the Diffie-Hellman
    * key exchange
    */
   SHA_Init(&exhashbase);
   sha_string(&exhashbase, localstr, strcspn(localstr, "\r\n"));
   sha_string(&exhashbase, remotestr, strlen(remotestr));
   return(0);
}

/*
 * Run SSH negotiation process
 */
short SSH_Connect(char *username, char *password, char *keyfile)
{
int status;

   /* Initialize important variables */
   SSH2_init();

   /* Wait for host version packet */
   sock_wait_input(&GlobalConfig.s, sock_delay, NULL, &status);

   /* Version string exchange and verification */
   if(SSH_Exchange_Identification())
	return(1);

   /*
    * Now we wait for host key exchange. This will also do
    * our key exchange, done by the transport layer
    */
   if(Configuration & VERBOSE_MODE)
        puts("Receiving host's key exchange packet");
   if(SSH_pkt_read(SSH_MSG_KEXINIT))
	return(1);

   /* Now we encrypt, hash and maybe compress */
   Configuration |= CIPHER_ENABLED;
   if((Configuration & COMPRESSION_REQUESTED))
	Request_Compression(6);

   /*
    * Request authorization and wait a response to it.
    */
   SSH_pkt_init(SSH_MSG_SERVICE_REQUEST);
   SSH_putstring("ssh-userauth");
   if(Configuration & VERBOSE_MODE)
        puts("Requesting authorization");
   SSH_pkt_send();
   if(SSH_pkt_read(SSH_MSG_SERVICE_ACCEPT))
	return(1);

   /*
    * Try public key authentication first
    * Then keyboard-interactive
    * Then password authentication
    */
   if(SSH2_Auth_Pubkey(username, keyfile))
      if(SSH2_Auth_KbdInt(username, password))
         if(SSH2_Auth_Password(username, password))
	    return(1);

   /* Open a channel */
   SSH2_Channel_Open();

   return(0);

sock_err:
   switch(status){
	case 1:
	   puts(ConnectionClosed);
	   break;

	case -1:
	   puts(RemoteClosed);
	   break;
   }
   return(1);
}
