/* channel.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.3 $
 *
 * This module is the connection layer.
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
#include <conio.h>
#include <string.h>

#include "config.h"
#include "macros.h"
#include "ssh.h"
#include "transprt.h"

/* external functions, data */
extern Packet pktin;		/* incoming SSH2 packet */
extern unsigned short Configuration;	/* configuration bitfields */
extern char *protocolerror;

/* local static data */
static unsigned long local_channel = 1974;   /* local channel number */
static unsigned long remote_channel;	     /* remote channel number */
static unsigned long remote_window;	     /* recipient's window size */

/*
 * Initialize an outgoing SSH2 channel packet.
 */
void SSH2_Channel_PktInit(unsigned char type)
{
   SSH_pkt_init(type);
   SSH_putuint32(remote_channel);
}

/*
 * Get a packet from the connection layer.
 * If type != NULL, also checks type to avoid protocol confusion
 * Returns 1 if: transport layer error
 *		 protocol error
 *		 type is not what we expected
 */
short SSH2_Channel_Read(unsigned char type)
{
char *str;
unsigned long len;

restart:
   if(SSH_pkt_read(0)) /* Get packet from transport layer */
	return(1);

   switch(pktin.type){
        case SSH_MSG_GLOBAL_REQUEST:    /* reject all global requests */
           SSH_getstring(&str, &len);
           if(SSH_getbool()){
                SSH_pkt_init(SSH_MSG_REQUEST_FAILURE);
                SSH_pkt_send();
           } /* if */
           goto restart;

        case SSH_MSG_CHANNEL_OPEN:      /* reject channel open requests */
           SSH_getstring(&str, &len);  /* dwell channel type */
           len = SSH_getuint32();      /* get channel number */
           SSH_pkt_init(SSH_MSG_CHANNEL_OPEN_FAILURE);
           SSH_putuint32(len);
           SSH_putuint32(1);           /* prohibited */
           SSH_putuint32(0);
           SSH_putuint32(0);
           SSH_pkt_send();
           goto restart;

        case SSH_MSG_IGNORE:
	   return(0);

        default:
           break;
   } /* switch */

   if(pktin.type < 80 || pktin.type > 100){ /* if not a channel packet */
	SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	return(1);
   }

   if(SSH_getuint32() != local_channel){ /* if not our channel */
	SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Received data for invalid channel");
	return(1);
   }

   switch(pktin.type){
	case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:	/* let these through */
	case SSH_MSG_CHANNEL_OPEN_FAILURE:
	case SSH_MSG_CHANNEL_SUCCESS:
	case SSH_MSG_CHANNEL_FAILURE:
	   break;

	case SSH_MSG_CHANNEL_DATA:	/* adjust window space if data */
	case SSH_MSG_CHANNEL_EXTENDED_DATA:
	   if(pktin.type == SSH_MSG_CHANNEL_DATA)
                len = GET_32BIT_MSB_FIRST(pktin.ptr);
           else
                len = GET_32BIT_MSB_FIRST(pktin.ptr + 4);
	   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_WINDOW_ADJUST);
	   SSH_putuint32(len);
	   SSH_pkt_send();
	   break;

	case SSH_MSG_CHANNEL_WINDOW_ADJUST: /* adjust remote window space */
	   remote_window += SSH_getuint32();
	   goto restart;

	case SSH_MSG_CHANNEL_EOF: /* Remote sent EOF, dwell it... */
	   goto restart;

	case SSH_MSG_CHANNEL_CLOSE: /* Remote closed channel, we close */
	   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_CLOSE);
	   SSH_pkt_send();
	   break;

	case SSH_MSG_CHANNEL_REQUEST: /* ignore requests now */
// FIXME: we may return the exit status code...
//	   SSH_getstring(&str, &len); /* get request type */
//	   if(!strcmp(str, "exit-status") || !strcmp(str, "exit-signal"))
//	      return status or signal
	   goto restart;

	default:
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
   } /* switch */

   if(type)
	if(pktin.type != type){
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
	}
   return(0);
}

/*
 * Open an SSH2 channel
 */
short SSH2_Channel_Open(void)
{
char *str;
unsigned long len;

   if(Configuration & VERBOSE_MODE)
        puts("Opening session channel");
   SSH_pkt_init(SSH_MSG_CHANNEL_OPEN);
   SSH_putstring("session");
   SSH_putuint32(local_channel);
   SSH_putuint32(MAX_PACKET_SIZE);	/* initial local window size */
   SSH_putuint32(MAX_PACKET_SIZE);	/* max packet size */
   SSH_pkt_send();

   if(SSH2_Channel_Read(0))
	return(1);

   switch(pktin.type){
        case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
           remote_channel = SSH_getuint32(); /* remote channel ID */
           remote_window = SSH_getuint32();  /* initial remote window size */
           break;

        case SSH_MSG_CHANNEL_OPEN_FAILURE:
           SSH_getuint32(); /* reason code */
           SSH_getstring(&str, &len);
           str[len] = '\0';
	   puts(str);
	   return(1);

        default:
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
   }
   return(0);
}

/*
 * Send n data bytes as an SSH packet and shrink remote
 * window accordingly
 */
void SSH2_Channel_Send(unsigned char *buff, unsigned short len)
{
   /* FIXME: check remote window size before sending data */
   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_DATA);
   SSH_putuint32(len);
   SSH_putdata(buff, len);
   SSH_pkt_send();
   remote_window -=len;
}
