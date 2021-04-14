/* sftpdos.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * Most parts are taken from the PuTTY source.
 *
 * $Date: 2005/12/30 16:26:41 $
 * $Revision: 1.6 $
 *
 * This module is the sftp frontend. Most parts are taken from
 * the PuTTY source
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
#include <sys/stat.h> 
#include <direct.h>

#include "tcp.h"
#include "channel.h"
#include "common.h"
#include "config.h"
#include "macros.h"
#include "sftp.h"
#include "ssh.h"
#include "transprt.h"
#include "version.h"
#include "negotiat.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

#define TRUE 1
#define FALSE 0

/* external functions */
SendFuncPtr SendPacket;

/* external structures, variables */
extern Packet pktin;	/* incoming SSH2 packet */
extern Packet pktout;	/* outgoing SSH2 packet */
extern char *RemoteClosed;
extern char *ConnectionClosed;
extern char *protocolerror;

/* global variables */
Config GlobalConfig;		/* global configuration structure */
unsigned short Configuration;	/* Configuration bits */

/* local variables */
static char *pwd, *homedir;
static char *RemoteHost = NULL;
static char *UserName = NULL;
static char *PassWord = NULL;
static char *KeyFile = NULL;
static unsigned short RemotePort = SSH_PORT;
static FILE *BatchFile = NULL;

/*
 * Initialize global variables
 */
static void Config_Init(void)
{
   SendPacket = SSH2_Channel_Send;
   GlobalConfig.debugfile = NULL;
   GlobalConfig.brailab = NULL;
   Configuration = 0;
}

/*
 * Progress meter
 */
static void progress(uint64 fsize, uint64 cursize)
{
unsigned short ratio, i;

   if(fsize.lo < 0x8000000)
      ratio = 32 * cursize.lo / fsize.lo;
   else if(!fsize.lo)
      ratio = 32;
   else
      ratio = 32 * (cursize.lo/32) / (fsize.lo/32);
   i = 30 * ratio / 32;
   cprintf("|%.*s%*s| %lu kB\r", i, "***********************************",
           30 - i, "", cursize.lo/1024);
}

/*
 * Start sftp subsystem on remote host
 */
static short SFTP_Start(void)
{
   if(Configuration & VERBOSE_MODE)
        puts("Starting SFTP subsystem");
   SSH2_Channel_PktInit(SSH_MSG_CHANNEL_REQUEST);
   SSH_putstring("subsystem");
   SSH_putbool(1);
   SSH_putstring("sftp");
   SSH_pkt_send();

   if(SSH2_Channel_Read(0))
	return(1);

   switch(pktin.type){
        case SSH_MSG_CHANNEL_SUCCESS:
           break;

        case SSH_MSG_CHANNEL_FAILURE:
           SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "Cannot run sftp subsystem");
	   return(1);

        default:
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
   }
   return(0);
}


/*
 * Connect to a host
 */
static int SFTP_Connect(char *hostname, char *username,
			char *password, char *keyfile)
{
   /* connect to server */
   TCPConnect(hostname, RemotePort);

   SSH_Connect(username, password, keyfile);

   /* Start SFTP subsystem */
   if(SFTP_Start())
	return(1);

   return(0);
}

/*
 * Allocate the concatenation of N strings.
 * Terminate arg list with NULL.
 */
static char *dupcat(char *s1, ...)
{
    int len;
    char *p, *q, *sn;
    va_list ap;

    len = strlen(s1);
    va_start(ap, s1);
    while (1) {
	sn = va_arg(ap, char *);
	if (!sn)
	    break;
	len += strlen(sn);
    }
    va_end(ap);

    if((p = malloc(len + 1)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    strcpy(p, s1);
    q = p + strlen(p);

    va_start(ap, s1);
    while (1) {
	sn = va_arg(ap, char *);
	if (!sn)
	    break;
	strcpy(q, sn);
	q += strlen(q);
    }
    va_end(ap);

    return p;
}


/*
 * Attempt to canonify a pathname starting from the pwd. If
 * canonification fails, at least fall back to returning a _valid_
 * pathname (though it may be ugly, eg /home/simon/../foobar).
 */
char *canonify(char *name)
{
    char *fullname, *canonname;

    if(name[0] == '/') {
	fullname = strdup(name);
    } else {
	char *slash;
	if(pwd[strlen(pwd) - 1] == '/')
	    slash = "";
	else
	    slash = "/";
	fullname = dupcat(pwd, slash, name, NULL);
    }

    canonname = fxp_realpath(fullname);

    if(canonname) {
	free(fullname);
	return canonname;
    } else {
	/*
	 * Attempt number 2. Some FXP_REALPATH implementations
	 * (glibc-based ones, in particular) require the _whole_
	 * path to point to something that exists, whereas others
	 * (BSD-based) only require all but the last component to
	 * exist. So if the first call failed, we should strip off
	 * everything from the last slash onwards and try again,
	 * then put the final component back on.
	 * 
	 * Special cases:
	 * 
	 *  - if the last component is "/." or "/..", then we don't
	 *    bother trying this because there's no way it can work.
	 * 
	 *  - if the thing actually ends with a "/", we remove it
	 *    before we start. Except if the string is "/" itself
	 *    (although I can't see why we'd have got here if so,
	 *    because surely "/" would have worked the first
	 *    time?), in which case we don't bother.
	 * 
	 *  - if there's no slash in the string at all, give up in
	 *    confusion (we expect at least one because of the way
	 *    we constructed the string).
	 */

	int i;
	char *returnname;

	i = strlen(fullname);
	if(i > 2 && fullname[i - 1] == '/')
	    fullname[--i] = '\0';      /* strip trailing / unless at pos 0 */
	while (i > 0 && fullname[--i] != '/');

	/*
	 * Give up on special cases.
	 */
	if(fullname[i] != '/' ||      /* no slash at all */
	    !strcmp(fullname + i, "/.") ||	/* ends in /. */
	    !strcmp(fullname + i, "/..") ||	/* ends in /.. */
	    !strcmp(fullname, "/")) {
	    return fullname;
	}

	/*
	 * Now i points at the slash. Deal with the final special
	 * case i==0 (ie the whole path was "/nonexistentfile").
	 */
	fullname[i] = '\0';	       /* separate the string */
	if(i == 0) {
	    canonname = fxp_realpath("/");
	} else {
	    canonname = fxp_realpath(fullname);
	}

	if(!canonname)
	    return fullname;	       /* even that failed; give up */

	/*
	 * We have a canonical name for all but the last path
	 * component. Concatenate the last component and return.
	 */
	returnname = dupcat(canonname,
			    canonname[strlen(canonname) - 1] ==
			    '/' ? "" : "/", fullname + i + 1, NULL);
	free(fullname);
	free(canonname);
	return returnname;
    }
}

/*
 * Return a pointer to the portion of str that comes after the last
 * slash (or backslash or colon, if `local' is TRUE).
 */
static char *stripslashes(char *str, int local)
{
    char *p;

    if(local) {
        p = strchr(str, ':');
        if(p) str = p+1;
    }

    p = strrchr(str, '/');
    if(p) str = p+1;

    if(local) {
	p = strrchr(str, '\\');
	if(p) str = p+1;
    }

    return str;
}

/*
 * Close SSH and TCP connection if open and free compression memory
 */
static void CloseConnection(void)
{
   if(Configuration & SFTP_CONNECTED){
        SSH2_Channel_PktInit(SSH_MSG_CHANNEL_EOF); /* send EOF */
        SSH_pkt_send();
	SSH2_Channel_Read(SSH_MSG_CHANNEL_CLOSE);
        sock_close(&GlobalConfig.s);   /* Close TCP socket */
   }

#if !defined (__386__)
   if(Configuration & COMPRESSION_ENABLED)
	Disable_Compression();
#endif


}

/* ----------------------------------------------------------------------
 * Actual sftp commands.
 */
struct sftp_command {
    char **words;
    int nwords, wordssize;
    int (*obey) (struct sftp_command *);	/* returns <0 to quit */
};

static int sftp_cmd_null(struct sftp_command *cmd)
{
    return 1;			       /* success */
}

static int sftp_cmd_unknown(struct sftp_command *cmd)
{
    printf("sftp: unknown command \"%s\"\n", cmd->words[0]);
    return 0;			       /* failure */
}

static int sftp_cmd_quit(struct sftp_command *cmd)
{
   CloseConnection();

   return -1;
}

/*
 * List a directory. If no arguments are given, list pwd; otherwise
 * list the directory given in words[1].
 */
static int sftp_ls_compare(const void *av, const void *bv)
{
    const struct fxp_name *const *a = (const struct fxp_name *const *) av;
    const struct fxp_name *const *b = (const struct fxp_name *const *) bv;
    return strcmp((*a)->filename, (*b)->filename);
}
int sftp_cmd_ls(struct sftp_command *cmd)
{
    struct fxp_handle *dirh;
    struct fxp_names *names;
    struct fxp_name **ournames;
    int nnames, namesize;
    char *dir, *cdir;
    int i;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2)
	dir = ".";
    else
	dir = cmd->words[1];

    cdir = canonify(dir);
    if(!cdir) {
	printf("%s: %s\n", dir, fxp_error());
	return 0;
    }

    printf("Listing directory %s\n", cdir);

    dirh = fxp_opendir(cdir);
    if(dirh == NULL) {
	printf("Unable to open %s: %s\n", dir, fxp_error());
    } else {
	nnames = namesize = 0;
	ournames = NULL;

	while (1) {

	    names = fxp_readdir(dirh);
	    if(names == NULL) {
		if(fxp_error_type() == SSH_FX_EOF)
		    break;
		printf("Reading directory %s: %s\n", dir, fxp_error());
		break;
	    }
	    if(names->nnames == 0) {
		fxp_free_names(names);
		break;
	    }

	    if(nnames + names->nnames >= namesize) {
		namesize += names->nnames + 128;
		if((ournames = realloc(ournames, namesize * sizeof(*ournames))) == NULL)
                   fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	    }

	    for(i = 0; i < names->nnames; i++)
		ournames[nnames++] = fxp_dup_name(&names->names[i]);

	    fxp_free_names(names);
	}
	fxp_close(dirh);

	/*
	 * Now we have our filenames. Sort them by actual file
	 * name, and then output the longname parts.
	 */
	qsort(ournames, nnames, sizeof(*ournames), sftp_ls_compare);

	/*
	 * And print them.
	 */
	for(i = 0; i < nnames; i++) {
	    printf("%s\n", ournames[i]->longname);
	    fxp_free_name(ournames[i]);
	}
	free(ournames);
    }

    free(cdir);

    return 1;
}

/*
 * Change directories. We do this by canonifying the new name, then
 * trying to OPENDIR it. Only if that succeeds do we set the new pwd.
 */
int sftp_cmd_cd(struct sftp_command *cmd)
{
    struct fxp_handle *dirh;
    char *dir;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2)
	dir = strdup(homedir);
    else
	dir = canonify(cmd->words[1]);

    if(!dir) {
	printf("%s: %s\n", dir, fxp_error());
	return 0;
    }

    dirh = fxp_opendir(dir);
    if(!dirh) {
	printf("Directory %s: %s\n", dir, fxp_error());
	free(dir);
	return 0;
    }

    fxp_close(dirh);

    free(pwd);
    pwd = dir;
    printf("Remote directory is now %s\n", pwd);

    return 1;
}

/*
 * Print current directory. Easy as pie.
 */
int sftp_cmd_pwd(struct sftp_command *cmd)
{
    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    printf("Remote directory is %s\n", pwd);
    return 1;
}

/*
 * Get a file and save it at the local end. We have two very
 * similar commands here: `get' and `reget', which differ in that
 * `reget' checks for the existence of the destination file and
 * starts from where a previous aborted transfer left off.
 */
int sftp_general_get(struct sftp_command *cmd, int restart)
{
    struct fxp_handle *fh;
    struct fxp_attrs fa;
    char *fname, *outfname, *buffer;
    uint64 offset;
    FILE *fp;
    int ret;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("get: expects a filename");
	return 0;
    }

    fname = canonify(cmd->words[1]);
    if(!fname) {
	printf("%s: %s\n", cmd->words[1], fxp_error());
	return 0;
    }
    outfname = (cmd->nwords == 2 ?
		stripslashes(cmd->words[1], 0) : cmd->words[2]);

    fh = fxp_open(fname, SSH_FXF_READ);
    if(!fh) {
	printf("%s: %s\n", fname, fxp_error());
	free(fname);
	return 0;
    }

    if(restart) {
	fp = fopen(outfname, "rb+");
    } else {
	fp = fopen(outfname, "wb");
    }

    if(!fp) {
	printf("local: unable to open %s\n", outfname);
	fxp_close(fh);
	free(fname);
	return 0;
    }

    if(restart) {
	long posn;
	fseek(fp, 0L, SEEK_END);
	posn = ftell(fp);
	printf("reget: restarting at file position %ld\n", posn);
	offset = uint64_make(0, posn);
    } else {
	offset = uint64_make(0, 0);
    }

    printf("remote:%s => local:%s\n", fname, outfname);

    fxp_fstat(fh, &fa);

    ret = 1;
    if((buffer = malloc(TRANSBUF_SIZE)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    while (1) {
	int len;
	int wpos, wlen;

	len = fxp_read(fh, buffer, offset, TRANSBUF_SIZE);
	if((len == -1 && fxp_error_type() == SSH_FX_EOF) || len == 0)
	    break;
	if(len == -1) {
	    printf("error while reading: %s\n", fxp_error());
	    ret = 0;
	    break;
	}

	wpos = 0;
	while (wpos < len) {
	    wlen = fwrite(buffer, 1, len - wpos, fp);
	    if(wlen <= 0) {
		puts("error while writing local file");
		ret = 0;
		break;
	    }
	    wpos += wlen;
	}
	if(wpos < len) {	       /* we had an error */
	    ret = 0;
	    break;
	}
	offset = uint64_add32(offset, len);
	if(!(Configuration & QUIET_MODE))
           progress(fa.size, offset);
    }

    free(buffer);
    if(!(Configuration & QUIET_MODE))
        cputs("\r\n");
    fclose(fp);
    fxp_close(fh);
    free(fname);

    return ret;
}
int sftp_cmd_get(struct sftp_command *cmd)
{
    return sftp_general_get(cmd, 0);
}
int sftp_cmd_reget(struct sftp_command *cmd)
{
    return sftp_general_get(cmd, 1);
}

/*
 * Send a file and store it at the remote end. We have two very
 * similar commands here: `put' and `reput', which differ in that
 * `reput' checks for the existence of the destination file and
 * starts from where a previous aborted transfer left off.
 */
int sftp_general_put(struct sftp_command *cmd, int restart)
{
    struct fxp_handle *fh;
    struct stat fa;
    char *fname, *origoutfname, *outfname, *buffer;
    uint64 localsize, offset;
    FILE *fp;
    int ret;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("put: expects a filename");
	return 0;
    }

    fname = cmd->words[1];
    origoutfname = (cmd->nwords == 2 ?
		    stripslashes(cmd->words[1], 1) : cmd->words[2]);
    outfname = canonify(origoutfname);
    if(!outfname) {
	printf("%s: %s\n", origoutfname, fxp_error());
	return 0;
    }

    fp = fopen(fname, "rb");
    if(!fp) {
	printf("local: unable to open %s\n", fname);
	free(outfname);
	return 0;
    }

    fstat(fileno(fp), &fa);
    localsize = uint64_make(0, fa.st_size);

    if(restart) {
	fh = fxp_open(outfname,
		      SSH_FXF_WRITE);
    } else {
	fh = fxp_open(outfname,
		      SSH_FXF_WRITE | SSH_FXF_CREAT | SSH_FXF_TRUNC);
    }
    if(!fh) {
	printf("%s: %s\n", outfname, fxp_error());
	free(outfname);
	return 0;
    }

    if(restart) {
	char decbuf[30];
	struct fxp_attrs attrs;
	if(!fxp_fstat(fh, &attrs)) {
	    printf("read size of %s: %s\n", outfname, fxp_error());
	    free(outfname);
	    return 0;
	}
	if(!(attrs.flags & SSH_FILEXFER_ATTR_SIZE)) {
	    printf("read size of %s: size was not given\n", outfname);
	    free(outfname);
	    return 0;
	}
	offset = attrs.size;
	uint64_decimal(offset, decbuf);
	printf("reput: restarting at file position %s\n", decbuf);
	if(fseek(fp, offset.lo, SEEK_SET) != 0)
	    fseek(fp, 0, SEEK_END);    /* *shrug* */
    } else {
	offset = uint64_make(0, 0);
    }

    printf("local:%s => remote:%s\n", fname, outfname);

    ret = 1;
    if((buffer = malloc(TRANSBUF_SIZE)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    while (1) {
	int len;
	len = fread(buffer, 1, TRANSBUF_SIZE, fp);
	if(len == -1) {
	    puts("error while reading local file");
	    ret = 0;
	    break;
	} else if(len == 0) {
	    break;
	}
	if(!fxp_write(fh, buffer, offset, len)) {
	    printf("error while writing: %s\n", fxp_error());
	    ret = 0;
	    break;
	}
	offset = uint64_add32(offset, len);
	if(!(Configuration & QUIET_MODE))
           progress(localsize, offset);
    }

    free(buffer);
    if(!(Configuration & QUIET_MODE))
        cputs("\r\n");
    fxp_close(fh);
    fclose(fp);
    free(outfname);

    return ret;
}
int sftp_cmd_put(struct sftp_command *cmd)
{
    return sftp_general_put(cmd, 0);
}
int sftp_cmd_reput(struct sftp_command *cmd)
{
    return sftp_general_put(cmd, 1);
}

int sftp_cmd_mkdir(struct sftp_command *cmd)
{
    char *dir;
    int result;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("mkdir: expects a directory");
	return 0;
    }

    dir = canonify(cmd->words[1]);
    if(!dir) {
	printf("%s: %s\n", dir, fxp_error());
	return 0;
    }

    result = fxp_mkdir(dir);
    if(!result) {
	printf("mkdir %s: %s\n", dir, fxp_error());
	free(dir);
	return 0;
    }

    free(dir);
    return 1;
}

int sftp_cmd_rmdir(struct sftp_command *cmd)
{
    char *dir;
    int result;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("rmdir: expects a directory");
	return 0;
    }

    dir = canonify(cmd->words[1]);
    if(!dir) {
	printf("%s: %s\n", dir, fxp_error());
	return 0;
    }

    result = fxp_rmdir(dir);
    if(!result) {
	printf("rmdir %s: %s\n", dir, fxp_error());
	free(dir);
	return 0;
    }

    free(dir);
    return 1;
}

int sftp_cmd_rm(struct sftp_command *cmd)
{
    char *fname;
    int result;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("rm: expects a filename");
	return 0;
    }

    fname = canonify(cmd->words[1]);
    if(!fname) {
	printf("%s: %s\n", fname, fxp_error());
	return 0;
    }

    result = fxp_remove(fname);
    if(!result) {
	printf("rm %s: %s\n", fname, fxp_error());
	free(fname);
	return 0;
    }

    free(fname);
    return 1;
}

int sftp_cmd_mv(struct sftp_command *cmd)
{
    char *srcfname, *dstfname;
    int result;

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: not connected, use \"open user@hostname\"");
	return 0;
    }

    if(cmd->nwords < 3) {
	puts("mv: expects two filenames");
	return 0;
    }
    srcfname = canonify(cmd->words[1]);
    if(!srcfname) {
	printf("%s: %s\n", srcfname, fxp_error());
	return 0;
    }

    dstfname = canonify(cmd->words[2]);
    if(!dstfname) {
	printf("%s: %s\n", dstfname, fxp_error());
	return 0;
    }

    result = fxp_rename(srcfname, dstfname);
    if(!result) {
	char const *error = fxp_error();
	struct fxp_attrs attrs;

	/*
	 * The move might have failed because dstfname pointed at a
	 * directory. We check this possibility now: if dstfname
	 * _is_ a directory, we re-attempt the move by appending
	 * the basename of srcfname to dstfname.
	 */
	result = fxp_stat(dstfname, &attrs);
	if(result &&
	    (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) &&
	    (attrs.permissions & 0040000)) {
	    char *p;
	    char *newname, *newcanon;
	    printf("(destination %s is a directory)\n", dstfname);
	    p = srcfname + strlen(srcfname);
	    while (p > srcfname && p[-1] != '/') p--;
	    newname = dupcat(dstfname, "/", p, NULL);
	    newcanon = canonify(newname);
	    free(newname);
	    if(newcanon) {
		free(dstfname);
		dstfname = newcanon;
		result = fxp_rename(srcfname, dstfname);
		error = result ? NULL : fxp_error();
	    }
	}
	if(error) {
	    printf("mv %s %s: %s\n", srcfname, dstfname, error);
	    free(srcfname);
	    free(dstfname);
	    return 0;
	}
    }
    printf("%s -> %s\n", srcfname, dstfname);

    free(srcfname);
    free(dstfname);
    return 1;
}

static int SFTP_Init(void)
{
    /*
     * Do protocol initialisation. 
     */
    if(!fxp_init()) {
	printf("Unable to initialize SFTP: %s\n", fxp_error());
	return 1;		       /* failure */
    }

    /*
     * Find out where our home directory is.
     */
    homedir = fxp_realpath(".");
    if(!homedir) {
	printf("Warning: failed to resolve home directory: %s\n",
		fxp_error());
	homedir = strdup(".");
    } else {
	printf("Remote working directory is %s\n", homedir);
    }
    pwd = strdup(homedir);
    return 0;
}

static int sftp_cmd_open(struct sftp_command *cmd)
{
char *s;

    if(Configuration & SFTP_CONNECTED){
	puts("sftpdos: already connected");
	return 0;
    }

    if(cmd->nwords < 2) {
	puts("open: expects a user@host name");
	return 0;
    }

    if((s = strchr(cmd->words[1], '@')) == NULL){
	puts("open: expects a user@host name");
	return 0;
    }

    *s++ = '\0';

    if(SFTP_Connect(s, cmd->words[1], NULL, NULL))
	return 0;

    if(SFTP_Init())
        return 0;

    Configuration += SFTP_CONNECTED;

    return 1;
}

static int sftp_cmd_close(struct sftp_command *cmd)
{

    if(!(Configuration & SFTP_CONNECTED)){
	puts("sftpdos: no connection");
	return 0;
    }

    CloseConnection();

    Configuration -= CIPHER_ENABLED;
    Configuration -= COMPRESSION_ENABLED;
    Configuration -= SFTP_CONNECTED;

    return 1;
}

static int sftp_cmd_lcd(struct sftp_command *cmd)
{
char *currdir;

    if(cmd->nwords < 2) {
	puts("lcd: expects a local directory name");
	return 0;
    }

    chdir(cmd->words[1]);

    if((currdir = malloc(256)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    getcwd(currdir, 256);
    printf("New local directory is %s\n", currdir);
    free(currdir);

    return 1;
}

static int sftp_cmd_lpwd(struct sftp_command *cmd)
{
char *currdir;

    if((currdir = malloc(256)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    getcwd(currdir, 256);
    printf("Current working directory is %s\n", currdir);
    free(currdir);

    return 1;
}

static int sftp_cmd_pling(struct sftp_command *cmd)
{
    int exitcode;

    exitcode = system(cmd->words[1]);
    return (exitcode == 0);
}

static int sftp_cmd_help(struct sftp_command *cmd);

static struct sftp_cmd_lookup {
    char *name;
    /*
     * For help purposes, there are two kinds of command:
     * 
     *  - primary commands, in which `longhelp' is non-NULL. In
     *    this case `shorthelp' is descriptive text, and `longhelp'
     *    is longer descriptive text intended to be printed after
     *    the command name.
     * 
     *  - alias commands, in which `longhelp' is NULL. In this case
     *    `shorthelp' is the name of a primary command, which
     *    contains the help that should double up for this command.
     */
    int listed;			       /* do we list this in primary help? */
    char *shorthelp;
    char *longhelp;
    int (*obey) (struct sftp_command *);
} sftp_lookup[] = {
    /*
     * List of sftp commands. This is binary-searched so it MUST be
     * in ASCII order.
     */
    {
	"!", TRUE, "run a local DOS command",
	    "<command>\n"
	    "  Runs a local DOS command. For example, \"!del myfile\".\n",
	    sftp_cmd_pling
    },
    {
	"bye", TRUE, "finish your SFTP session",
	    "\n"
	    "  Terminate SFTP session and quit SFTPDOS.\n",
	    sftp_cmd_quit
    },
    {
	"cd", TRUE, "change your remote working directory",
	    " [ <New working directory> ]\n"
	    "  Change the remote working directory.\n"
	    "  If a new working directory is not supplied, you will be\n"
	    "  returned to your home directory.\n",
	    sftp_cmd_cd
    },
    {
        "close", TRUE, "close current connection",
            "\n"
            "   Close the connection without quitting SFTPDOS.\n",
            sftp_cmd_close
    },
    {
	"del", TRUE, "delete a file",
	    " <filename>\n"
	    "  Delete a file.\n",
	    sftp_cmd_rm
    },
    {
	"delete", FALSE, "del", NULL, sftp_cmd_rm
    },
    {
	"dir", TRUE, "list contents of a remote directory",
	    " [ <directory-name> ]\n"
	    "  List the contents of a specified directory on the host.\n"
	    "  If <directory-name> is not given, the current working directory\n"
	    "  will be listed.\n",
	    sftp_cmd_ls
    },
    {
	"exit", TRUE, "bye", NULL, sftp_cmd_quit
    },
    {
	"get", TRUE, "download a file from the host",
	    " <filename> [ <local-name> ]\n"
	    "  Downloads a file and stores it locally under the same\n"
	    "  or a given name <local-name>.\n",
	    sftp_cmd_get
    },
    {
	"help", TRUE, "give help",
	    " [ <command> [ <command> ... ] ]\n"
	    "  Give general help if no commands are specified.\n"
	    "  If one or more commands are specified, give help on\n"
	    "  those commands.\n",
	    sftp_cmd_help
    },
    {
	"lcd", TRUE, "change local working directory",
	    " <local-directory-name>\n"
	    "  Change the local working directory (the default location\n"
	    "  where the \"get\" command will save files).\n",
	    sftp_cmd_lcd
    },
    {
	"lpwd", TRUE, "print local working directory",
	    "\n"
	    "  Print the local working directory (the default location\n"
	    "  where the \"get\" command will save files).\n",
	    sftp_cmd_lpwd
    },
    {
	"ls", TRUE, "dir", NULL,
	    sftp_cmd_ls
    },
    {
	"mkdir", TRUE, "create a directory on the remote host",
	    " <directory-name>\n"
	    "  Creates a directory with the given name on the host.\n",
	    sftp_cmd_mkdir
    },
    {
	"mv", TRUE, "move or rename a file on the remote host",
	    " <source-filename> <destination-filename>\n"
	    "  Moves or renames the file <source-filename> on the host,\n"
	    "  so that it is accessible under the name <destination-filename>.\n",
	    sftp_cmd_mv
    },
    {
	"open", TRUE, "connect to a host",
	    " [<user>@]<hostname>\n"
	    "  Establishes an SFTP connection to a given host. Only usable\n"
	    "  when you did not already specify a host name on the command\n"
	    "  line.\n",
	    sftp_cmd_open
    },
    {
	"put", TRUE, "upload a file from your local machine to the host",
	    " <filename> [ <remote-name> ]\n"
	    "  Uploads a file to the host and stores it there under\n"
	    "  the same or a given name <remote-name>\n",
	    sftp_cmd_put
    },
    {
	"pwd", TRUE, "print your remote working directory",
	    "\n"
	    "  Print the current remote working directory for your SFTP session.\n",
	    sftp_cmd_pwd
    },
    {
	"quit", TRUE, "bye", NULL,
	    sftp_cmd_quit
    },
    {
	"reget", TRUE, "continue downloading a file",
	    " <filename> [ <local-filename> ]\n"
	    "  Works exactly like the \"get\" command, but the local file\n"
	    "  must already exist. The download will begin at the end of the\n"
	    "  file. This is for resuming a download that was interrupted.\n",
	    sftp_cmd_reget
    },
    {
	"ren", TRUE, "mv", NULL,
	    sftp_cmd_mv
    },
    {
	"rename", FALSE, "mv", NULL,
	    sftp_cmd_mv
    },
    {
	"reput", TRUE, "continue uploading a file",
	    " <filename> [ <remote-filename> ]\n"
	    "  Works exactly like the \"put\" command, but the remote file\n"
	    "  must already exist. The upload will begin at the end of the\n"
	    "  file. This is for resuming an upload that was interrupted.\n",
	    sftp_cmd_reput
    },
    {
	"rm", TRUE, "del", NULL,
	    sftp_cmd_rm
    },
    {
	"rmdir", TRUE, "remove a directory on the remote host",
	    " <directory-name>\n"
	    "  Removes the directory with the given name on the host.\n"
	    "  The directory will not be removed unless it is empty.\n",
	    sftp_cmd_rmdir
    }
};

const struct sftp_cmd_lookup *lookup_command(char *name)
{
    int i, j, k, cmp;

    i = -1;
    j = sizeof(sftp_lookup) / sizeof(*sftp_lookup);
    while (j - i > 1) {
	k = (j + i) / 2;
	cmp = strcmp(name, sftp_lookup[k].name);
	if(cmp < 0)
	    j = k;
	else if(cmp > 0)
	    i = k;
	else {
	    return &sftp_lookup[k];
	}
    }
    return NULL;
}

static int sftp_cmd_help(struct sftp_command *cmd)
{
    int i;
    if(cmd->nwords == 1) {
	/*
	 * Give short help on each command.
	 */
	int maxlen;
	maxlen = 0;
	for(i = 0; i < sizeof(sftp_lookup) / sizeof(*sftp_lookup); i++) {
	    int len;
	    if(!sftp_lookup[i].listed)
		continue;
	    len = strlen(sftp_lookup[i].name);
	    if(maxlen < len)
		maxlen = len;
	}
	for(i = 0; i < sizeof(sftp_lookup) / sizeof(*sftp_lookup); i++) {
	    const struct sftp_cmd_lookup *lookup;
	    if(!sftp_lookup[i].listed)
		continue;
	    lookup = &sftp_lookup[i];
	    printf("%-*s", maxlen+2, lookup->name);
	    if(lookup->longhelp == NULL)
		lookup = lookup_command(lookup->shorthelp);
	    printf("%s\n", lookup->shorthelp);
	}
    } else {
	/*
	 * Give long help on specific commands.
	 */
	for(i = 1; i < cmd->nwords; i++) {
	    const struct sftp_cmd_lookup *lookup;
	    lookup = lookup_command(cmd->words[i]);
	    if(!lookup) {
		printf("help: %s: command not found\n", cmd->words[i]);
	    } else {
		printf("%s", lookup->name);
		if(lookup->longhelp == NULL)
		    lookup = lookup_command(lookup->shorthelp);
		printf("%s", lookup->longhelp);
	    }
	}
    }
    return 1;
}

/* ----------------------------------------------------------------------
 * Command line reading and parsing.
 */
struct sftp_command *sftp_getcmd(FILE *fp)
{
    char *line;
    int linelen, linesize;
    struct sftp_command *cmd;
    char *p, *q, *r;
    int quoting;

    printf("sftpdos> ");
    fflush(stdout);

    if((cmd = malloc(sizeof(struct sftp_command))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    cmd->words = NULL;
    cmd->nwords = 0;
    cmd->wordssize = 0;

    line = NULL;
    linesize = linelen = 0;
    while (1) {
	int len;
	char *ret;

	linesize += 512;
	if((line = realloc(line, linesize)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	ret = fgets(line + linelen, linesize - linelen, fp);

	if(!ret || (linelen == 0 && line[0] == '\0')) {
	    cmd->obey = sftp_cmd_quit;
            puts("quit");
	    return cmd;		       /* eof */
	}
	len = linelen + strlen(line + linelen);
	linelen += len;
	if(line[linelen - 1] == '\n') {
	    linelen--;
	    line[linelen] = '\0';
	    break;
	}
    }

    if(BatchFile)
	printf("%s\n", line);

    p = line;
    while (*p && (*p == ' ' || *p == '\t'))
	p++;

    if(*p == '!') {
	/*
	 * Special case: the ! command. This is always parsed as
	 * exactly two words: one containing the !, and the second
	 * containing everything else on the line.
	 */
	cmd->nwords = cmd->wordssize = 2;
	if((cmd->words = realloc(cmd->words, cmd->wordssize * sizeof(char *))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	cmd->words[0] = strdup("!");
	cmd->words[1] = strdup(p+1);
    } else {

	/*
	 * Parse the command line into words. The syntax is:
	 *  - double quotes are removed, but cause spaces within to be
	 *    treated as non-separating.
	 *  - a double-doublequote pair is a literal double quote, inside
	 *    _or_ outside quotes. Like this:
	 *
	 *      firstword "second word" "this has ""quotes"" in" and""this""
	 *
	 * becomes
	 *
	 *      >firstword<
	 *      >second word<
	 *      >this has "quotes" in<
	 *      >and"this"<
	 */
	while (*p) {
	    /* skip whitespace */
	    while (*p && (*p == ' ' || *p == '\t'))
		p++;
	    /* mark start of word */
	    q = r = p;		       /* q sits at start, r writes word */
	    quoting = 0;
	    while (*p) {
		if(!quoting && (*p == ' ' || *p == '\t'))
		    break;		       /* reached end of word */
		else if(*p == '"' && p[1] == '"')
		    p += 2, *r++ = '"';    /* a literal quote */
		else if(*p == '"')
		    p++, quoting = !quoting;
		else
		    *r++ = *p++;
	    }
	    if(*p)
		p++;		       /* skip over the whitespace */
	    *r = '\0';
	    if(cmd->nwords >= cmd->wordssize) {
		cmd->wordssize = cmd->nwords + 16;
 		if((cmd->words = realloc(cmd->words, cmd->wordssize * sizeof(char *))) == NULL)
                   fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	    }
	    cmd->words[cmd->nwords++] = strdup(q);
	}
    }

    free(line);

    /*
     * Now parse the first word and assign a function.
     */

    if(cmd->nwords == 0)
	cmd->obey = sftp_cmd_null;
    else {
	const struct sftp_cmd_lookup *lookup;
	lookup = lookup_command(cmd->words[0]);
	if(!lookup)
	    cmd->obey = sftp_cmd_unknown;
	else
	    cmd->obey = lookup->obey;
    }

    return cmd;
}

/*
 * Client loop
 */
static void dosession(void)
{
struct sftp_command *cmd;
int ret, i;

   if(!BatchFile){
        /*
        * Now we're ready to do Real Stuff.
        */
        while(1){
	   cmd = sftp_getcmd(stdin);
	   if(!cmd)
	        break;
	   ret = cmd->obey(cmd);
           if(cmd->words) {
	      for(i = 0; i < cmd->nwords; i++)
	         free(cmd->words[i]);
	      free(cmd->words);
	   }
	   free(cmd);
	   if(ret < 0)
	      break;
	} /* while */
   } /* if */
   else{
	while(1){
	   cmd = sftp_getcmd(BatchFile);
	   if (!cmd)
		break;
	   ret = cmd->obey(cmd);
	   if(ret < 0)
		break;
        } /* while */
	fclose(BatchFile);
   } /* else */
}

/* Get command line arguments */

static void getargs(int argc, char *argv[])
{
unsigned short i;
char *s;
#if defined (__386__)
   char *usage="Usage: sftpd386 [options] [username@remotehost]\n"
#else
   char *usage="Usage: sftpdos [options] [username@remotehost]\n"
#endif
	    "Options:\n"
	    "-i <identity file>      - key file for public key authentication\n"
	    "-p <port number>        - remote port\n"
	    "-s <password>           - remote password\n"
	    "-b <batch file>         - batch mode (plain text file)\n"
	    "-P                      - use non privileged local port\n"
	    "-C                      - enable compression\n"
	    "-d                      - save SSH packets to debug.pkt\n"
	    "-v                      - verbose output\n"
	    "-q                      - disable progess meter";

   for(i = 1; i < argc; ++i){
	s = argv[i];
	if(*s != '-') break;
	switch (*++s){
	   case '\0':
		fatal(usage);
		return;

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

	   case 'p':
		if(*++s)
		   RemotePort = atoi(s);
		else if(++i < argc)
		   RemotePort = atoi(argv[i]);
		else
		   fatal(usage);
		continue;

	   case 'P':
		Configuration += NONPRIVILEGED_PORT;
		continue;

	   case 'C':
		Configuration += COMPRESSION_REQUESTED;
		continue;

	   case 'd':
		if((GlobalConfig.debugfile = fopen("debug.pkt","w+")) == NULL)
		   fatal("Cannot create debug file");
		else
		   fputs("\n-------------------\n",GlobalConfig.debugfile);
		continue;

	   case 'b':
		if(*++s){
		   if((BatchFile = fopen(s,"rt")) == NULL)
			fatal("Cannot open batch file");
		}
		else if(++i < argc){
		   if((BatchFile = fopen(argv[i],"rt")) == NULL)
			fatal("Cannot open batch file");
		}
		else
		   fatal(usage);
		continue;

	   case 'v':
		Configuration += VERBOSE_MODE;
		continue;

	   case 'q':
		Configuration += QUIET_MODE;
		continue;

	   default:
		fatal(usage);
	} /* end switch */

   } /* end for */

   /* no_more_options */
   if(i == argc)   /* no user@host specified */
	return;

   if((s = strchr(argv[i],'@')) == NULL)
        fatal(usage);

   *s++ = '\0';

   UserName = argv[i];
   RemoteHost = s;
}

/*
 * Main program. Parse arguments etc.
 */
int main(int argc, char *argv[])
{
#if defined (__386__)
   printf("SFTPDOS v%s. 386+ version\n", SSH_VERSION);
#else
   printf("SFTPDOS v%s\n", SSH_VERSION);
#endif
   printf("%s\n", AUTHOR_1);
   printf("%s\n\n", AUTHOR_2);
      
   Config_Init();	/* Initialize global variables */
   srand(time(NULL));	/* Initialize random number generator */

   getargs(argc, argv);	/* Process command line */

   /*
    * If a user@host string has already been provided, connect to
    * it now.
    */
   if(RemoteHost){
	if(SFTP_Connect(RemoteHost, UserName, PassWord, KeyFile))
	    return 1;
	if(SFTP_Init())
	    return 1;
        Configuration += SFTP_CONNECTED;
   }
   else
	puts("No hostname specified, use \"open user@hostname\" to connect");

   /* Start session */
   dosession();

   /* Close open file */
   if(GlobalConfig.debugfile)
	fclose(GlobalConfig.debugfile);

   return 0;
}
