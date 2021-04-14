/* auth.c       Copyright (c) 2000-2005 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.4 $
 *
 * This module is the authentication layer.
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
#include <conio.h>
#include <string.h>

#include "auth.h"
#include "config.h"
#include "macros.h"
#include "pubkey.h"
#include "ssh.h"
#include "transprt.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

/* external functions, data */
extern Packet pktin;		/* incoming SSH2 packet */
extern Packet pktout;		/* outgoing SSH2 packet */
extern unsigned char ssh2_session_id[20]; /* session ID */
extern Config GlobalConfig;		/* configuration variables */
extern unsigned short Configuration;	/* configuration bitfields */
extern struct ssh2_userkey ssh2_wrong_passphrase;
extern char *protocolerror;

/*
 * Allocate memory for password and ask for password.
 * Don't forget to free it later.
 */
static char *AskPassword(void)
{
char *password;
unsigned short len = 0;
unsigned char ch;

   // flush kb input
   while(kbhit()){
      getch();
   }

   if((password = (char *)malloc(MAX_PASSWORD_LENGTH * sizeof(char))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   while((ch = getch()) != 0x0d && len < MAX_PASSWORD_LENGTH){
	if(ch == 8 && len > 0)
		password[--len] = 0;
	else if(ch >= 32)
		password[len++] = ch;
   } /* while */
   password[len] = '\0';
   cputs("\r\n");
   return(password);
}


/*
 * Send ignore packet to make protocol analisys harder
 */
static void SendIgnores(void)
{
unsigned char randbuf[100];
unsigned short j, k;

   j = 10 + rand() % (sizeof(randbuf) - 10);
   for(k = 0; k < j; k++)
	randbuf[k] = rand() % 256;	/* fill random buffer */

   SSH_pkt_init(SSH_MSG_IGNORE);
   SSH_putdata(randbuf, j);
   SSH_pkt_send();
}

/*
 * Try public key authentication
 */
short SSH2_Auth_Pubkey(char *username, char *keyfile)
{
int type, i;
char *password = NULL, *comment;
unsigned char *pkblob, *sigblob, *sigdata;
int pkblob_len, sigblob_len, sigdata_len;
struct ssh2_userkey *key;

   if(keyfile == NULL) /* is there a key file? */
	return(1);       /* go and try password authentication */

   if(Configuration & VERBOSE_MODE)
	puts("Begin public key authentication");

   /* Check key */
   type = key_type(keyfile);
   if(type != SSH_KEYTYPE_SSH2 && type != SSH_KEYTYPE_OPENSSH){
	if(Configuration & VERBOSE_MODE)
	   printf("Key is of wrong type (%s)\r\n", key_type_to_str(type));
	return(1);       /* go and try password authentication */
   }

   /* Check if encrypted */
   if(type == SSH_KEYTYPE_SSH2)
        i = ssh2_userkey_encrypted(keyfile, &comment);
   else{
        /* OpenSSH doesn't do key comments */
	comment = strdup(keyfile);
	i = openssh_encrypted(keyfile);
   }

   /* Get passphrase if encrypted */
   if(i){
	cprintf("Passphrase for key \"%.100s\": ", comment);
	password = AskPassword();
   } /* if */
   else
	if(Configuration & VERBOSE_MODE)
	   puts("No passphrase required");
   free(comment);

   /* Try to load key */
   if(type == SSH_KEYTYPE_SSH2)
        key = ssh2_load_userkey(keyfile, password);
   else
        key = openssh_read(keyfile, password);

   if(password)
        free(password);

   if(key == SSH2_WRONG_PASSPHRASE){
	puts("Wrong passphrase");
        return(1);       /* go and try password authentication */
   }

   /*
    * First, offer the public blob to see if the server is
    * willing to accept it.
    */
   pkblob = key->alg->public_blob(key->data, &pkblob_len);

   SSH2_Auth_PktInit(SSH_MSG_USERAUTH_REQUEST, username);
   SSH_putstring("publickey");
   SSH_putbool(0);
   SSH_putstring(key->alg->name);
   SSH_putuint32(pkblob_len);
   SSH_putdata(pkblob, pkblob_len);
   SSH_pkt_send();

   if(SSH2_Auth_Read(NULL))
	return(1);

   switch(pktin.type){
        case SSH_MSG_USERAUTH_PK_OK:
           break;

        case SSH_MSG_USERAUTH_FAILURE:
	   puts("Host refused our key");
           return(1);

        default:
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
   }

   /*
    * Now attempt a serious authentication using the key
    */
   SSH2_Auth_PktInit(SSH_MSG_USERAUTH_REQUEST, username);
   SSH_putstring("publickey");
   SSH_putbool(1);
   SSH_putstring(key->alg->name);
   SSH_putuint32(pkblob_len);
   SSH_putdata(pkblob, pkblob_len);

   /* The data to be signed is:
    *
    *   string  session-id
    *
    * followed by everything so far placed in the
    * outgoing packet.
    */

   sigdata_len = pktout.length + 4 + 20;
   if((sigdata = (unsigned char *)malloc(sigdata_len)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   PUT_32BIT_MSB_FIRST(sigdata, 20);
   memcpy(sigdata + 4, ssh2_session_id, 20);
   memcpy(sigdata + 24, pktout.body, pktout.length);
   sigblob = key->alg->sign(key->data, sigdata, sigdata_len, &sigblob_len);
   SSH_putuint32(sigblob_len);
   SSH_putdata(sigblob, sigblob_len);
   free(pkblob);
   free(sigblob);
   free(sigdata);
   SSH_pkt_send();

   if(SSH2_Auth_Read(SSH_MSG_USERAUTH_SUCCESS))
	return(1);

   return(0);
}

/*
 * Try password authentication, max three times
 */
short SSH2_Auth_Password(char *username, char *password)
{
unsigned short n = 1;
unsigned long j;
char *p;

   if(Configuration & VERBOSE_MODE)
        puts("Trying password authentication");
   if(!password){
	printf("Password: ");
        fflush(stdout);
	if(GlobalConfig.brailab)
	   fputs("Password: ", GlobalConfig.brailab);
	password = AskPassword();
	n++;
   }

nextpass:
   SSH2_Auth_PktInit(SSH_MSG_USERAUTH_REQUEST, username);
   SSH_putstring("password");
   SSH_putbool(0);
   SSH_putstring(password);
   SSH_pkt_send();
   free(password);
   SendIgnores();

restart:
   if(SSH2_Auth_Read(NULL))
	return(1);

   switch(pktin.type) {
	case SSH_MSG_USERAUTH_SUCCESS:	/* OK */
	   break;

        case SSH_MSG_USERAUTH_PASSWD_CHANGEREQ: /* password expired */
           SSH_getstring(&p, &j);
           p[j] = 0;
           cputs(p);
	   SSH2_Auth_PktInit(SSH_MSG_USERAUTH_REQUEST, username);
           SSH_putstring("password");
           SSH_putbool(1);
           SSH_putstring(password); /* old password */
	   password = AskPassword();
           SSH_putstring(password); /* new password */
           SSH_pkt_send();
           free(password);
           goto restart;

	case SSH_MSG_USERAUTH_FAILURE: 	/* try again */
	   if(n-- == 0){
		SSH_Disconnect(SSH_DISCONNECT_AUTH_CANCELLED_BY_USER, "Invalid password");
		return(1);
	   }
	   cputs("Password: ");
	   if(GlobalConfig.brailab)
		fputs("Password: ", GlobalConfig.brailab);
	   password = AskPassword();
	   goto nextpass;
   } /* switch */
   return(0);
}

/*
 * Try keyboard interactive authentication, max three times
 */
short SSH2_Auth_KbdInt(char *username, char *password)
{
unsigned short attempts = 3;
unsigned long prompts, i, j;
unsigned char echo;
char *p, *userinputs;

   if(Configuration & VERBOSE_MODE)
        puts("Trying keyboard-interactive authentication");

nextkbd:
   SSH2_Auth_PktInit(SSH_MSG_USERAUTH_REQUEST, username);
   SSH_putstring("keyboard-interactive");
   SSH_putstring(""); // language tag
   SSH_putstring(""); // submethod
   SSH_pkt_send();

restartkbd:
   if(SSH2_Auth_Read(NULL))
	return(1);

   switch(pktin.type) {
	case SSH_MSG_USERAUTH_SUCCESS:	/* OK */
	   break;

        case SSH_MSG_USERAUTH_INFO_REQUEST: /* info req */
           SSH_getstring(&p, &j); // name
           if(j)
              puts(p);
           SSH_getstring(&p, &j); // instruction
           if(j)
              puts(p);
           SSH_getstring(&p, &j); // lang tag
           prompts = SSH_getuint32(); // num-prompts
           if(prompts){
	      if((userinputs = (char *)malloc(prompts * 256)) == NULL)
                 fatal("Memory allocation error. %s: %d", __FILE__, __LINE__); // 256 per input should be enough
              for(i = 0; i < prompts; i++){
                 SSH_getstring(&p, &j); // prompt
		 SSH_getbool();
                 if(prompts == 1 && password){  /* try password from command line */
		    p = password;
		 } else {
                    if(j){
                       printf("%s", p);
		       fflush(stdout);
	               if(GlobalConfig.brailab){
		          fprintf(GlobalConfig.brailab, "%s", p);
		       }
		    }
		    p = AskPassword();
		 }
	         strcpy(userinputs + i * 256, p);
                 if(prompts >= 1)
	            free(p);
              }
	   }
           SSH_pkt_init(SSH_MSG_USERAUTH_INFO_RESPONSE);
           SSH_putuint32(prompts);      // num-prompts
           if(prompts){
              for(i = 0; i < prompts; i++){
                 SSH_putstring(userinputs + i * 256);   // put responses
              }
	      free(userinputs);
	   }
	   SSH_pkt_send();
	   SendIgnores();
           goto restartkbd;

	case SSH_MSG_USERAUTH_FAILURE: 	/* try again */
	   if(--attempts == 0){
		return(1); // password auth comes next
	   }
	   goto nextkbd;
   } /* switch */
   return(0);
}

/*
 * Initialize an outgoing SSH2 authentication packet.
 */
void SSH2_Auth_PktInit(char type, char *username)
{
   SSH_pkt_init(type);
   SSH_putstring(username);
   SSH_putstring("ssh-connection");
}

/*
 * Get a packet from the authentication layer.
 * If type != NULL, also checks type to avoid protocol confusion
 */
short SSH2_Auth_Read(unsigned char type)
{
char *str;
unsigned long len;

restart:
   if(SSH_pkt_read(NULL)) /* Get packet from transport layer */
	return(1);

   switch(pktin.type){
	case SSH_MSG_USERAUTH_FAILURE:	/* let these through */
	case SSH_MSG_USERAUTH_SUCCESS:
        case SSH_MSG_USERAUTH_PK_OK: /* and SSH_MSG_USERAUTH_PASSWD_CHANGEREQ */
        case SSH_MSG_USERAUTH_INFO_RESPONSE:
	   break;

	case SSH_MSG_USERAUTH_BANNER:	/* display banner */
           SSH_getstring(&str, &len);
           str[len] = 0;
           puts(str);
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
