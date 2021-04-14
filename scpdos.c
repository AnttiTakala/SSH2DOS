/* scpdos.c       Copyright (c) 2000-2005 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.5 $
 *
 * Based on the PuTTY scp source.
 * Copyright (c)Joris van Rantwijk, Simon Tatham
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
#include <stdarg.h>
#include <dos.h>
#include <sys/stat.h>
#include <direct.h>
#include <sys/utime.h>

#include "tcp.h"
#include "ssh.h"
#include "transprt.h"
#include "channel.h"
#include "version.h"
#include "config.h"
#include "common.h"
#include "negotiat.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

#define TRANSBUF_SIZE 8192
#define SCP_SINK_FILE   1
#define SCP_SINK_DIR    2
#define SCP_SINK_ENDDIR 3
#define SCP_SINK_RETRY  4	       /* not an action; just try again */

#define MKDIR(p,a)  mkdir (p)

struct scp_sink_action {	/* SCP control block */
   char action;			/* FILE, DIR, ENDDIR */
   char *buf;			/* will need freeing after use */
   char *name;			/* filename or dirname (not ENDDIR) */
   int mode;			/* access mode (not ENDDIR) */
   unsigned long size;		/* file size (not ENDDIR) */
   char settime;		/* 1 if atime and mtime are filled */
   unsigned long atime, mtime;	/* access times for the file */
};

/* external functions */
SendFuncPtr SendPacket;

/* external structures, variables */
extern Packet pktin;	/* incoming SSH packet */

/* global variables */
Config GlobalConfig;		/* global configuration structure */
unsigned short Configuration;   /* Configuration bits */

/* local variables */
static short firstarg;		/* first argument, which is not a switch */
static char command[256];	/* buffer for the command to send */
static char TargetShouldBeDirectory = 0; /* nomen est omen */
static char IsDir = 0;		/* is it really a directory? */
static FILE *fr;		/* File handle */
static char *localfile;		/* pointer to local filename */
static char *remotefile;	/* pointer to remote filename */
static char *transbuffer;	/* buffer for sending files */
static unsigned pendlen = 0;	/* we have unused SCP control bytes */
static char *pendbuf = NULL;	/* buffer for unused SCP control bytes */
static char local;		/* decide copying direction */
static char *RemoteHost = NULL;
static char *UserName = NULL;
static char *PassWord = NULL;
static char *KeyFile = NULL;
static unsigned short RemotePort = SSH_PORT;

/* local functions begin here */
static short rsource(char *);

/*
 * Get the size of a file
 */
static unsigned long Getfilesize(char *s)
{
struct stat ss;

   stat(s, &ss);
   return(ss.st_size);
}

/*
 * Get the creation time of a file
 */
static unsigned long Getfiletime(char *s)
{
struct stat ss;
   stat(s, &ss);
   return(ss.st_atime);
}

/*
 * Get attributes of a file, return error if doesn't exist
 */
static int Getfileattr(char *s)
{
struct stat ss;
int j;

   j = stat(s, &ss);
   if(j)
	return(j);
   else
	return(ss.st_mode);
}

/*
 * Determine whether a string is entirely composed of dots
 */
static int is_dots(char *str)
{
   return str[strspn(str, ".")] == '\0';
}

/*
 * Return a pointer to the portion of str that comes after the last
 * slash (or backslash or colon, if `local' is TRUE).
 */
static char *stripslashes(char *str, int local)
{
char *p;

   if(local){
	p = strchr(str, ':');
	if (p) str = p+1;
   }

   p = strrchr(str, '/');
   if(p)
	str = p+1;

   if(local){
	p = strrchr(str, '\\');
	if (p) str = p+1;
   }

   return str;
}

/*
 * Allocate the concatenation of N strings. Terminate arg list with NULL
 */
static char *dupcat(char *s1, ...)
{
int len;
char *p, *q, *sn;
va_list ap;

   len = strlen(s1);
   va_start(ap, s1);
   while(1){
	sn = va_arg(ap, char *);
	if(!sn)
	   break;
	len += strlen(sn);
   }
   va_end(ap);

   p = malloc(len + 1);
   strcpy(p, s1);
   q = p + strlen(p);

   va_start(ap, s1);
   while(1){
	sn = va_arg(ap, char *);
	if(!sn)
	   break;
	strcpy(q, sn);
	q += strlen(q);
   }
   va_end(ap);

   return p;
}

/*
 * Initialize global variables
 */
static void Config_Init(void)
{
   SendPacket = SSH2_Channel_Send;
   GlobalConfig.debugfile = NULL;
   Configuration = 0;
}

/*
 * Send a command to be executed on the remote host
 */
void sendcommand(void)
{
   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_REQUEST);
   SSH_putstring("exec");
   SSH_putbool(1);
   SSH_putstring(command);
   SSH_pkt_send();
   SSH2_Channel_Read(SSH_MSG_CHANNEL_SUCCESS);
}

/*
 * Get command line arguments
 */
static void getargs(int argc, char *argv[])
{
int i, j, remote = 0;
char *s;

struct find_t ffblk;

#if defined (__386__)
   char usage[]="Usage: scp2d386 [options] from to\n"
#else
   char usage[]="Usage: scp2dos [options] from to\n"
#endif
            "from = <localfile | username@remotehost:remotefile>\n"
            "  to = <localfile | username@remotehost:remotefile>\n"
	    "Wildcards are accepted.\n"
	    "Options:\n"
	    "-i <identity file>     - identity file\n"
	    "-p                     - preserve file attributes\n"
	    "-r                     - recursively copy directories\n"
	    "-l                     - convert sent filenames to lowercase\n"
	    "-v                     - verbose output\n"
	    "-q                     - disable progess meter\n"
	    "-C                     - enable compression\n"
	    "-P <port>              - remote port number\n"
	    "-s                     - remote password\n"
	    "-d                     - save SSH packets to debug.pkt"
            ;
   for (i = 1; i < argc; ++i){
	s = argv[i];
	if(*s != '-')
	   break;
	switch (*++s){
	   case '\0':
	    fatal(usage);
	    return;

	   case 'i':
		if (*++s)
		   KeyFile = s;
		else if (++i < argc)
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

	   case 'p':
		Configuration |= PRESERVE_ATTRIBUTES;
		continue;

	   case 'l':
		Configuration |= CONVERT_LOWERCASE;
		continue;

	   case 'r':
		Configuration |= RECURSIVE_COPY;
		continue;

	   case 'v':
		Configuration |= VERBOSE_MODE;
		continue;

	   case 'q':
		Configuration |= QUIET_MODE;
		continue;

	   case 'C':
		Configuration |= COMPRESSION_REQUESTED;
		continue;

	   case 'P':
		if(*++s)
		   RemotePort = atoi(s);
		else if(++i < argc)
		   RemotePort = atoi(argv[i]);
		else
		   fatal(usage);
		continue;

	   case 'd':
		if((GlobalConfig.debugfile = fopen("debug.pkt","w+")) == NULL)
		   fatal("Cannot create debug file");
		else
		   fputs("\n-------------------\n",GlobalConfig.debugfile);
		continue;

	   default:
		fatal(usage);
	} /* end switch */
   } /* end for */

/* no_more_options */
   if(i + 2 > argc)
	fatal(usage);

/*
 * Try and work out which file is remote and which file is local 
 * 
 * Works on the assumption that the "remote file" has to have a
 * "@" and a":" character.
 */

   if(strchr(argv[i],'@')!=NULL && strchr(argv[i],':')!=NULL)
	local = 1;
   if(strchr(argv[argc - 1],'@')!=NULL && strchr(argv[argc - 1],':')!=NULL)
	remote = 1;

   if((local == 1) && (remote == 1))
	fatal("Error - both files are remote");
   else if((local == 0) && (remote == 0))
	fatal("Error - both files are local");

   if(local){
	UserName = argv[i];
	RemoteHost = argv[i];
        localfile = argv[i+1];
   }
   else{
	UserName = argv[argc - 1];
	RemoteHost = argv[argc - 1];
   }

   firstarg = i;
   RemoteHost = strchr(UserName, '@');
   *RemoteHost++ = '\0';	/* kill '@' after username */

   remotefile = strchr(RemoteHost, ':');
   *remotefile++ = '\0';		/* kill ':' after hostname */

/*
 * Check if the specified thing is a directory,
 * more files or wildcards, and exists or not
 */

   if(local){ /* from remote to local */
	if(firstarg + 2 != argc)
	   fatal("More than one remote source not supported");
        j = Getfileattr(localfile);
	if((j != -1) && (j & S_IFDIR)) /* does it exist and is it a dir */
		IsDir = 1;
	if(strchr(remotefile, '*') || strchr(remotefile, '?')){
	   TargetShouldBeDirectory = 1;
           if(!IsDir) /* if local must be directory but it isn't, bomb out */
		fatal("Error - must specify a local directory");
	}
   } else { /* from local to remote */
	/* More local files, recursive mode or wildcards specified? */
	if((Configuration & RECURSIVE_COPY) || (firstarg + 2 < argc) ||
	    strchr(argv[firstarg], '*') || strchr(argv[firstarg], '?'))
		TargetShouldBeDirectory = 1;

	/* Examine local file(s) for existence */
	for(i = firstarg; i < argc - 1; i++)
           if(_dos_findfirst(argv[i], _A_SUBDIR, &ffblk))
		fatal("Error - %s not found", argv[i]);

	/* if no remote file specified, let it be a '.' */
	if(*remotefile <= ' ')
	   remotefile = ".";
   } /* else */
}

/*
 * Progress meter
 */
static void progress(unsigned long fsize, unsigned long cursize)
{
unsigned short ratio, i;

   if(fsize < 0x8000000)
      ratio = 32 * cursize / fsize;
   else if(!fsize)
      ratio = 32;
   else
      ratio = 32 * (cursize/32) / (fsize/32);
   i = 30 * ratio / 32;
   cprintf("|%.*s%*s| %lu kB\r", i, "***********************************",
           30 - i, "", cursize/1024);
}

/*
 * Send a file to the host
 */
static short source(char *file)
{
unsigned long FileSize, FileTime;
unsigned long len;
unsigned long sent;
unsigned long i;
char cmdbuf[80];
char *p;
int err;

   if(Configuration & CONVERT_LOWERCASE)
	strlwr(file); /* if we're asked to convert it to lowercase */
   /*
    * If we have a directory name here, we must check if recursive
    * mode enabled or not. If yes, do it, else warn
    */
   i = Getfileattr(file);
   if(i & S_IFDIR){
	if(Configuration & RECURSIVE_COPY){
	   p = strrchr(file, '\\');
	   if(!p)
		p = file;
	   else
		p++;
	   if(!strcmp(p, ".") || !strcmp(p, ".."))
		/* skip . and .. */ ;
	   else
		if(rsource(file))
		   return(1);
	} else {
	   printf("%s: not a regular file\n", file);
        }
        return(0);
   }

   /*
    * Now it's sure that we have a regular file here.
    * Get it's size and time, open it and send
    */
   FileSize = Getfilesize(file);
   FileTime = Getfiletime(file);

   if((fr = fopen(file, "rb")) == NULL){
	SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "Error - cannot open %s", fr);
        return(1);
   }

   /* preserve attributes if configured */
   if(Configuration & PRESERVE_ATTRIBUTES){
	sprintf(cmdbuf, "T%lu 0 %lu 0\n", FileTime, FileTime);
	SSH2_Channel_Send(cmdbuf, strlen(cmdbuf));
        err = Get_SCP_Response();
        if(err){
           return err;
        }
   }

   /* change '\' to '/' */
   for(i = 0; i < strlen(file); i++)
        if(file[i] == '\\')
	   file[i] = '/';

   /* we only need the file name without directory or drive name */
   if((p = strrchr(file, '/')) != NULL) /* search for \ */
      p++;
   else if((p = strrchr(file, ':')) != NULL) /* then for : */
      p++;
   else
      p = file;

   cprintf("%s (%lu bytes): \r\n", p, FileSize);

   /* send filename and size */
   sprintf(cmdbuf, "C%04o %lu %s\n", 0644, FileSize, p);
   SSH2_Channel_Send(cmdbuf, strlen(cmdbuf));
   err = Get_SCP_Response();
   if(err)
      return err;

   /* send file itself */
   sent = 0;
   transbuffer=(char *)malloc(TRANSBUF_SIZE * sizeof(char));
   for (i = 0; i < FileSize; i += TRANSBUF_SIZE){
	len = fread(transbuffer, 1, TRANSBUF_SIZE, fr);
	SSH2_Channel_Send(transbuffer, len);
	sent += len;
	if(!(Configuration & QUIET_MODE))
           progress(FileSize, sent);
   } /* for */

   /* finish SCP send */
   free(transbuffer);
   fclose(fr);
   SSH2_Channel_Send("", 1);
   err = Get_SCP_Response();
   if(err)
      return err;
   puts("");
   return(0);
}

/*
 *  Recursively send the contents of a directory.
 */
static short rsource(char *src)
{
char *findfile, *foundfile, *last;
char cmdbuf[80];
struct find_t ffblk;

   if((last = strrchr(src, '\\')) == NULL)
	last = src;
   else
	last++;
   if(strrchr(last, '\\'))
	last = strrchr(last, '\\') + 1;
   if(last == src && strchr(src, ':'))
	last = strchr(src, ':') + 1;

   if(Configuration & VERBOSE_MODE)
	printf("Entering directory: %s\n", last);
   sprintf(cmdbuf, "D%04o 0 %s\n", 0755, last);
   SSH2_Channel_Send(cmdbuf, strlen(cmdbuf));
   SSH2_Channel_Read(0);

   findfile = dupcat(src, "\\*.*", NULL);
   _dos_findfirst(findfile, _A_SUBDIR, &ffblk);
   free(findfile);
   do{
	if(!strcmp(ffblk.name, ".") ||
	   !strcmp(ffblk.name, ".."))	/* ignore . and .. */
		continue;
	foundfile = dupcat(src, "\\", ffblk.name, NULL);
	if(source(foundfile))
	   return(1);
	free(foundfile);
   } while(!_dos_findnext(&ffblk));
   if(Configuration & VERBOSE_MODE)
	printf("Leaving directory: %s\n", last);
   SSH2_Channel_Send("E\n", 2);
   SSH2_Channel_Read(0);

   return(0);
}

/*
 * Get data from the SSH layer to the SCP layer
 */
static int ssh_scp_recv(char *buf, int len)
{
   /*
    * If we have enough pending data, no problem. However,
    * if the SCP layer needs more than we have, we must
    * get enough data with blocking from the SSH layer
    */
restart:
   if (pendlen >= len) { /* we have enough? */
	memcpy(buf, pendbuf, len);
	memmove(pendbuf, pendbuf + len, pendlen - len);
	pendlen -= len;
	if(pendlen == 0){ /* if we have no more, free the buffer */
	   free(pendbuf);
	   pendbuf = NULL;
	} else
	   pendbuf = realloc(pendbuf, pendlen);
	return len;
    } else { /* we must wait for more input from the SSH layer */
        SSH2_Channel_Read(0);
	if(pktin.type == SSH_MSG_CHANNEL_CLOSE)
	   return(0);
	if(pktin.type == SSH_MSG_CHANNEL_DATA)
	   pktin.length -= 9;
	if(!pktin.length)
	   return(0);
	pendlen += pktin.length;
	pendbuf = (pendbuf ? realloc(pendbuf, pendlen) :
		malloc(pendlen));
        memcpy(pendbuf + pendlen - pktin.length, pktin.body + 9, pktin.length);
        goto restart;
    }
}


/*
 *  Wait for a response from the other side.
 *  Return 0 if ok, -1 if error.
 */
static int Get_SCP_Response(void)
{
char ch, resp, rbuf[2048];
int p;

   if(ssh_scp_recv(&resp, 1) <= 0)
      fatal("Lost connection");

   p = 0;
   switch (resp){
      case 0:			       /* ok */
         return (0);
      default:
	rbuf[p++] = resp;
	/* fallthrough */
      case 1:			       /* error */
      case 2:			       /* fatal error */
	do {
	    if (ssh_scp_recv((unsigned char *) &ch, 1) <= 0)
		fatal("Protocol error: Lost connection");
	    rbuf[p++] = ch;
	} while (p < sizeof(rbuf) && ch != '\n');
	rbuf[p - 1] = '\0';
	if (resp == 1)
	    puts(rbuf);
	else
	    fatal("%s", rbuf);
	return (-1);
    }
}


/*
 * Get the next SCP control packet and decide what to do
 */
static int scp_get_sink_action(struct scp_sink_action *act)
{
int i, done, bufsize, action;
char ch;

   act->settime = done = bufsize = 0;
   act->buf = NULL;

   while (!done) {
	if(ssh_scp_recv(&ch, 1) <= 0) /* get the command byte */
	   return(1);
        if (ch == '\n'){
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Protocol error: Unexpected newline");
           return(1);
        } /* if */
	i = 0;
	action = ch;
	do{ /* get the remaining command string */
	   if(ssh_scp_recv(&ch, 1) != 1)
		fatal("Lost connection");
	   if(i >= bufsize){
		bufsize = i + 128;
		act->buf = realloc(act->buf, bufsize);
	   }
	   act->buf[i++] = ch;
	} while (ch != '\n');
	act->buf[i - 1] = '\0';

        switch(action){
	   case '\01':	/* warning message */
	        puts(act->buf);
	        continue;

	   case '\0':	/* fatal error */
		SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "%s", act->buf);
		fatal("");

	   case 'E':	/* end of directory */
	        SSH2_Channel_Send("", 1);
	        act->action = SCP_SINK_ENDDIR;
	        return(0);

	   case 'T':	/* file time */
                if(sscanf(act->buf, "%ld %*d %ld %*d",
			   &act->mtime, &act->atime) == 2){
                   act->settime = 1;
		   SSH2_Channel_Send("", 1);
		   continue;	       /* go round again */
	        }
		SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Protocol error: Illegal time format");
                return(1);

	   case 'C':	/* create file */
	   case 'D':	/* create directory */
	        act->action = (action == 'C' ? SCP_SINK_FILE : SCP_SINK_DIR);
	        break;

	   default:
		SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Protocol error: Expected control record");
                return(1);
	} /* switch */
        done = 1;
   } /* while */
   if(sscanf(act->buf, "%o %lu %n", &act->mode, &act->size, &i) !=2){
	SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, "Protocol error: Illegal file descriptor format");
        return(1);
   }
   act->name = act->buf + i;
   return(0);
}

/*
 * Receive a file from the host
 */
static short sink(char *targ)
{
unsigned long received;
unsigned long gotbytes;
int attr, exists;
char *striptarget, *destfname;
struct scp_sink_action act;
struct utimbuf times;
short error;

   SSH2_Channel_Send("", 1);
   while(1){
	if(scp_get_sink_action(&act)) /* get command string from host */
	   return(1);
	if(act.action == SCP_SINK_ENDDIR)
	   return(0);
	if(act.action == SCP_SINK_RETRY)
	   continue;

        if(IsDir){
	    /*
	     * Prevent the remote side from maliciously writing to
	     * files outside the target area by sending a filename
	     * containing `../'. In fact, it shouldn't be sending
	     * filenames with any slashes or colons in at all; so
	     * we'll find the last slash, backslash or colon in the
	     * filename and use only the part after that. (And
	     * warn!)
	     */
            striptarget = stripslashes(act.name, 1);
	    if(striptarget != act.name){
		printf("Warning: remote host sent a compound pathname '%s'",
                   act.name);
		printf("         renaming local file to '%s'", striptarget);
	    }

	    /*
	     * Also check to see if the target filename is '.' or
	     * '..', or indeed '...'
	     */
	    if(is_dots(striptarget)){
		SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "Security violation: remote host attempted to write to"
		     " a '.' or '..' path!");
                return(1);
	    }
	    if (targ[0] != '\0')
		destfname = dupcat(targ, "\\", striptarget, NULL);
	    else
		destfname = strdup(striptarget);
        } else { /* plain file */
	    destfname = strdup(targ);
        }

	attr = Getfileattr(destfname);
	exists = (attr != -1);

	if(act.action == SCP_SINK_DIR){ /* create that directory */
           if(!exists){
		if(MKDIR(destfname, 666)){
		   SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "Cannot create directory %s", destfname);
                   return(1);
		}
	   }
	   if(sink(destfname))
		return(1);
	   continue;
        }

	/* It's sure that we have a regular filename here */
	error = 0;
	if((fr = fopen(destfname, "wb"))==NULL){
	   printf("Cannot create %s\n", destfname);
	   error++;
	}
        SSH2_Channel_Send("", 1);

	cprintf("%s (%lu bytes): \r\n", destfname, act.size);

	received = 0;
	if(!act.size){ /* size is zero */
           SSH2_Channel_Read(0);
	   progress(1, 1);
	} else {
	   while(received < act.size){
              SSH2_Channel_Read(0);
	      gotbytes = pktin.length - 9;
	      received += gotbytes;
	      if(gotbytes > act.size)
		 gotbytes = act.size;
	      else if(gotbytes > received - act.size)
		 gotbytes -= received - act.size;
	      if(!error)	/* write only if we could create this file */
		 fwrite(pktin.body + 9, 1, gotbytes, fr);
	      if(!(Configuration & QUIET_MODE))
		 progress(act.size, received);
	   } /* while */
	} /* else */

	if(!error)
	   fclose(fr);
	free(act.buf);
	if(act.settime){
	   times.modtime = act.mtime;
	   utime(destfname, &times);
	}
        free(destfname);
	SSH2_Channel_Send("", 1);
	puts("");
   } /* while */
}

/*
 * Receive files
 */
static short tolocal(void)
{
   sprintf(command, "scp%s%s%s -f %s",
        TargetShouldBeDirectory ? " -d" : "",
        Configuration & PRESERVE_ATTRIBUTES ? " -p" : "",
        Configuration & RECURSIVE_COPY ? " -r" : "",
	remotefile);
   sendcommand();
   puts("Receiving:");
   if(sink(localfile))
	return(1);

   return(0);
}

/*
 * Send files
 */
static short toremote(int argc, char *argv[])
{
struct find_t ffblk;

int i;
char *last, *srcpath, *filename;

   /* send SCP command to the server */
   sprintf(command, "scp%s%s%s -t %s",
        TargetShouldBeDirectory ? " -d" : "",
	Configuration & PRESERVE_ATTRIBUTES ? " -p" : "",
	Configuration & RECURSIVE_COPY ? " -r" : "",
	remotefile);
   sendcommand();
   SSH2_Channel_Read(0);

   puts("Sending:");

   /* Process all local file arguments */
   for(i = firstarg; i < argc - 1; i++){
	/*
	 * Trim off the last pathname component of `src', to
	 * provide the base pathname which will be prepended to
	 * filenames returned from Find{First,Next}File.
	 */
	srcpath = strdup(argv[i]);
	last = stripslashes(srcpath, 1);
	*last = '\0';

	/* sure it exists, we checked in getargs */
	_dos_findfirst(argv[i], _A_SUBDIR, &ffblk);
	do{
	   if(!strcmp(ffblk.name, ".") || /* don't bother with '.' */
	      !strcmp(ffblk.name, ".."))  /* and '..' */
                continue;
	   filename = dupcat(srcpath, ffblk.name, NULL);
	   if(source(filename))
		return(1);
	   free(filename);
        } while(!_dos_findnext(&ffblk));
        free(srcpath);
   } /* for */
   return(0);
}

/*
 * Main program starts here
 */
int main(int argc, char **argv)
{
#if defined (__386__)
   printf("SCP2DOS v%s. 386+ version\n", SSH_VERSION);
#else
   printf("SCP2DOS v%s\n", SSH_VERSION);
#endif
   printf("%s\n", AUTHOR_1);
   printf("%s\n\n", AUTHOR_2);
   
   Config_Init();	/* Initialize global variables */
   srand(time(NULL));	/* Initialize random number generator */

   getargs(argc, argv);	/* Process command line */

   TCPConnect(RemoteHost, RemotePort);  	/* Connect to server */

   SSH_Connect(UserName, PassWord, KeyFile);	/* begin SSH negotiation */

   /* Check which way we are transferring */
   if(!local){
        toremote(argc, argv);		/* from local to remote */
	SSH2_Channel_PktInit(SSH_MSG_CHANNEL_EOF);
	SSH_pkt_send();
        SSH2_Channel_Read(SSH_MSG_CHANNEL_CLOSE);
   }
   else
        tolocal();	/* from remote to local */

   if(pktin.body)
      free(pktin.body);

   SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "");

   if(Configuration & COMPRESSION_ENABLED)
	Disable_Compression();

   sock_close(&GlobalConfig.s);   /* Close TCP socket */

   /* Close open file */
   if(GlobalConfig.debugfile)
	fclose(GlobalConfig.debugfile);

   return(0);
}
