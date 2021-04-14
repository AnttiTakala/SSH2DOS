/*
 * sftp.c: SFTP generic client code.
 *
 * Taken from the PuTTY source.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "channel.h"
#include "int64.h"
#include "macros.h"
#include "sftp.h"
#include "ssh.h"
#include "transprt.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

/* external structures, variables */
extern Packet pktin;	/* incoming SSH packet */

/* local variables */
struct sftp_packet {
    unsigned char *data;
    unsigned long length, maxlen;
    unsigned long savedpos;
    int type;
};

static const char *fxp_error_message;
static int fxp_errtype;
static unsigned pendlen = 0;	/* we have unused SFTP bytes */
static char *pendbuf = NULL;	/* buffer for unused SFTP bytes */

/* ----------------------------------------------------------------------
 * SFTP packet construction functions.
 */
static void sftp_pkt_ensure(struct sftp_packet *pkt, int length)
{
    if (pkt->maxlen < length) {
	pkt->maxlen = length + 256;
	if((pkt->data = realloc(pkt->data, pkt->maxlen)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    }
}
static void sftp_pkt_adddata(struct sftp_packet *pkt, void *data, int len)
{
    pkt->length += len;
    sftp_pkt_ensure(pkt, pkt->length);
    memcpy(pkt->data + pkt->length - len, data, len);
}
static void sftp_pkt_addbyte(struct sftp_packet *pkt, unsigned char byte)
{
    sftp_pkt_adddata(pkt, &byte, 1);
}
static struct sftp_packet *sftp_pkt_init(int pkt_type)
{
    struct sftp_packet *pkt;
    if((pkt = malloc(sizeof(struct sftp_packet))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    pkt->data = NULL;
    pkt->savedpos = -1;
    pkt->length = 0;
    pkt->maxlen = 0;
    sftp_pkt_addbyte(pkt, (unsigned char) pkt_type);
    return pkt;
}
static void sftp_pkt_adduint32(struct sftp_packet *pkt,
			       unsigned long value)
{
    unsigned char x[4];
    PUT_32BIT_MSB_FIRST(x, value);
    sftp_pkt_adddata(pkt, x, 4);
}
static void sftp_pkt_adduint64(struct sftp_packet *pkt, uint64 value)
{
    unsigned char x[8];
    PUT_32BIT_MSB_FIRST(x, value.hi);
    PUT_32BIT_MSB_FIRST(x + 4, value.lo);
    sftp_pkt_adddata(pkt, x, 8);
}
static void sftp_pkt_addstring_start(struct sftp_packet *pkt)
{
    sftp_pkt_adduint32(pkt, 0);
    pkt->savedpos = pkt->length;
}
static void sftp_pkt_addstring_str(struct sftp_packet *pkt, char *data)
{
    sftp_pkt_adddata(pkt, data, strlen(data));
    PUT_32BIT_MSB_FIRST(pkt->data + pkt->savedpos - 4, pkt->length - pkt->savedpos);
}
static void sftp_pkt_addstring_data(struct sftp_packet *pkt,
				    char *data, int len)
{
    sftp_pkt_adddata(pkt, data, len);
    PUT_32BIT_MSB_FIRST(pkt->data + pkt->savedpos - 4, pkt->length - pkt->savedpos);
}
static void sftp_pkt_addstring(struct sftp_packet *pkt, char *data)
{
    sftp_pkt_addstring_start(pkt);
    sftp_pkt_addstring_str(pkt, data);
}
static void sftp_pkt_addattrs(struct sftp_packet *pkt, struct fxp_attrs attrs)
{
    sftp_pkt_adduint32(pkt, attrs.flags);
    if (attrs.flags & SSH_FILEXFER_ATTR_SIZE) {
	sftp_pkt_adduint32(pkt, attrs.size.hi);
	sftp_pkt_adduint32(pkt, attrs.size.lo);
    }
    if (attrs.flags & SSH_FILEXFER_ATTR_UIDGID) {
	sftp_pkt_adduint32(pkt, attrs.uid);
	sftp_pkt_adduint32(pkt, attrs.gid);
    }
    if (attrs.flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
	sftp_pkt_adduint32(pkt, attrs.permissions);
    }
    if (attrs.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
	sftp_pkt_adduint32(pkt, attrs.atime);
	sftp_pkt_adduint32(pkt, attrs.mtime);
    }
    if (attrs.flags & SSH_FILEXFER_ATTR_EXTENDED) {
	/*
	 * We currently don't support sending any extended
	 * attributes.
	 */
    }
}

/* ----------------------------------------------------------------------
 * SFTP packet decode functions.
 */

static unsigned char sftp_pkt_getbyte(struct sftp_packet *pkt)
{
    unsigned char value;
    if (pkt->length - pkt->savedpos < 1)
	return 0;		       /* arrgh, no way to decline (FIXME?) */
    value = (unsigned char) pkt->data[pkt->savedpos];
    pkt->savedpos++;
    return value;
}
static unsigned long sftp_pkt_getuint32(struct sftp_packet *pkt)
{
    unsigned long value;
    if (pkt->length - pkt->savedpos < 4)
	return 0;		       /* arrgh, no way to decline (FIXME?) */
    value = GET_32BIT_MSB_FIRST(pkt->data + pkt->savedpos);
    pkt->savedpos += 4;
    return value;
}
static void sftp_pkt_getstring(struct sftp_packet *pkt,
			       char **p, int *length)
{
    *p = NULL;
    if (pkt->length - pkt->savedpos < 4)
	return;
    *length = GET_32BIT_MSB_FIRST(pkt->data + pkt->savedpos);
    pkt->savedpos += 4;
    if (pkt->length - pkt->savedpos < *length)
	return;
    *p = pkt->data + pkt->savedpos;
    pkt->savedpos += *length;
}
static struct fxp_attrs sftp_pkt_getattrs(struct sftp_packet *pkt)
{
    struct fxp_attrs ret;
    ret.flags = sftp_pkt_getuint32(pkt);
    if (ret.flags & SSH_FILEXFER_ATTR_SIZE) {
	unsigned long hi, lo;
	hi = sftp_pkt_getuint32(pkt);
	lo = sftp_pkt_getuint32(pkt);
	ret.size = uint64_make(hi, lo);
    }
    if (ret.flags & SSH_FILEXFER_ATTR_UIDGID) {
	ret.uid = sftp_pkt_getuint32(pkt);
	ret.gid = sftp_pkt_getuint32(pkt);
    }
    if (ret.flags & SSH_FILEXFER_ATTR_PERMISSIONS) {
	ret.permissions = sftp_pkt_getuint32(pkt);
    }
    if (ret.flags & SSH_FILEXFER_ATTR_ACMODTIME) {
	ret.atime = sftp_pkt_getuint32(pkt);
	ret.mtime = sftp_pkt_getuint32(pkt);
    }
    if (ret.flags & SSH_FILEXFER_ATTR_EXTENDED) {
	int count;
	count = sftp_pkt_getuint32(pkt);
	while (count--) {
	    char *str;
	    int len;
	    /*
	     * We should try to analyse these, if we ever find one
	     * we recognise.
	     */
	    sftp_pkt_getstring(pkt, &str, &len);
	    sftp_pkt_getstring(pkt, &str, &len);
	}
    }
    return ret;
}
static void sftp_pkt_free(struct sftp_packet *pkt)
{
    if (pkt->data)
	free(pkt->data);
    free(pkt);
}

/* ----------------------------------------------------------------------
 * Send and receive packet functions.
 */
static void sftp_send(struct sftp_packet *pkt)
{
unsigned char x[4];

    PUT_32BIT_MSB_FIRST(x, pkt->length);
    SSH2_Channel_Send(x, 4);
    SSH2_Channel_Send(pkt->data, pkt->length);
    sftp_pkt_free(pkt);
}

/*
 * Get data from the SSH layer to the SFTP layer.
 * Return NULL if connecton is closed or error occured
 */
static int sftp_recvdata(char *buf, int len)
{
   /*
    * If we have enough pending data, no problem. However,
    * if the SFTP layer needs more than we have, we must
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
	} else {
	   if((pendbuf = realloc(pendbuf, pendlen)) == NULL){
              fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
           }
        }
	return len;
    } else { /* we must wait for more input from the SSH layer */
	if(SSH2_Channel_Read(SSH_MSG_CHANNEL_DATA))
	   return 0;
	pktin.length -= 9;
	pendlen += pktin.length;
	if((pendbuf = (pendbuf ? realloc(pendbuf, pendlen) :
		malloc(pendlen))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
        memcpy(pendbuf + pendlen - pktin.length, pktin.ptr + 4, pktin.length);
        goto restart;
    }
}

struct sftp_packet *sftp_recv(void)
{
    struct sftp_packet *pkt;
    unsigned char x[4];

    if (!sftp_recvdata(x, 4))
	return NULL;

    if((pkt = malloc(sizeof(struct sftp_packet))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    pkt->savedpos = 0;
    pkt->length = pkt->maxlen = GET_32BIT_MSB_FIRST(x);
    if((pkt->data = malloc(pkt->length)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

    if (!sftp_recvdata(pkt->data, pkt->length)) {
	sftp_pkt_free(pkt);
	return NULL;
    }

    pkt->type = sftp_pkt_getbyte(pkt);

    return pkt;
}

/* ----------------------------------------------------------------------
 * String handling routines.
 */

static char *mkstr(char *s, int len)
{
char *p;

    if((p = (char *)malloc(len + 1)) == NULL)
       fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

/* ----------------------------------------------------------------------
 * SFTP primitives.
 */

/*
 * Deal with (and free) an FXP_STATUS packet. Return 1 if
 * SSH_FX_OK, 0 if SSH_FX_EOF, and -1 for anything else (error).
 * Also place the status into fxp_errtype.
 */
static int fxp_got_status(struct sftp_packet *pktin)
{
    static const char *const messages[] = {
	/* SSH_FX_OK. The only time we will display a _message_ for this
	 * is if we were expecting something other than FXP_STATUS on
	 * success, so this is actually an error message! */
	"unexpected OK response",
	"end of file",
	"no such file or directory",
	"permission denied",
	"failure",
	"bad message",
	"no connection",
	"connection lost",
	"operation unsupported",
    };

    if (pktin->type != SSH_FXP_STATUS) {
	fxp_error_message = "expected FXP_STATUS packet";
	fxp_errtype = -1;
    } else {
	fxp_errtype = sftp_pkt_getuint32(pktin);
	if (fxp_errtype < 0 ||
	    fxp_errtype >= sizeof(messages) / sizeof(*messages))
		fxp_error_message = "unknown error code";
	else
	    fxp_error_message = messages[fxp_errtype];
    }

    if (fxp_errtype == SSH_FX_OK)
	return 1;
    else if (fxp_errtype == SSH_FX_EOF)
	return 0;
    else
	return -1;
}

static void fxp_internal_error(char *msg)
{
    fxp_error_message = msg;
    fxp_errtype = -1;
}

const char *fxp_error(void)
{
    return fxp_error_message;
}

int fxp_error_type(void)
{
    return fxp_errtype;
}

/*
 * Perform exchange of init/version packets. Return 0 on failure.
 */
int fxp_init(void)
{
    struct sftp_packet *pktout, *pktin;
    int remotever;

    pktout = sftp_pkt_init(SSH_FXP_INIT);
    sftp_pkt_adduint32(pktout, SFTP_PROTO_VERSION);
    sftp_send(pktout);

    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("could not connect");
	return 0;
    }
    if (pktin->type != SSH_FXP_VERSION) {
	fxp_internal_error("did not receive FXP_VERSION");
        sftp_pkt_free(pktin);
	return 0;
    }
    remotever = sftp_pkt_getuint32(pktin);
    if (remotever > SFTP_PROTO_VERSION) {
	fxp_internal_error
	    ("remote protocol is more advanced than we support");
        sftp_pkt_free(pktin);
	return 0;
    }
    /*
     * In principle, this packet might also contain extension-
     * string pairs. We should work through them and look for any
     * we recognise. In practice we don't currently do so because
     * we know we don't recognise _any_.
     */
    sftp_pkt_free(pktin);

    return 1;
}

/*
 * Canonify a pathname.
 */
char *fxp_realpath(char *path)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_REALPATH);
    sftp_pkt_adduint32(pktout, 0x123); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_str(pktout, path);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return NULL;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x123) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return NULL;
    }
    if (pktin->type == SSH_FXP_NAME) {
	int count;
	char *path;
	int len;

	count = sftp_pkt_getuint32(pktin);
	if (count != 1) {
	    fxp_internal_error("REALPATH returned name count != 1\n");
            sftp_pkt_free(pktin);
	    return NULL;
	}
	sftp_pkt_getstring(pktin, &path, &len);
	if (!path) {
	    fxp_internal_error("REALPATH returned malformed FXP_NAME\n");
            sftp_pkt_free(pktin);
	    return NULL;
	}
	path = mkstr(path, len);
	sftp_pkt_free(pktin);
	return path;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return NULL;
    }
}

/*
 * Open a file.
 */
struct fxp_handle *fxp_open(char *path, int type)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_OPEN);
    sftp_pkt_adduint32(pktout, 0x567); /* request id */
    sftp_pkt_addstring(pktout, path);
    sftp_pkt_adduint32(pktout, type);
    sftp_pkt_adduint32(pktout, 0);     /* (FIXME) empty ATTRS structure */
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return NULL;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x567) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return NULL;
    }
    if (pktin->type == SSH_FXP_HANDLE) {
	char *hstring;
	struct fxp_handle *handle;
	int len;

	sftp_pkt_getstring(pktin, &hstring, &len);
	if (!hstring) {
	    fxp_internal_error("OPEN returned malformed FXP_HANDLE\n");
            sftp_pkt_free(pktin);
	    return NULL;
	}
	if((handle = malloc(sizeof(struct fxp_handle))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	handle->hstring = mkstr(hstring, len);
	handle->hlen = len;
	sftp_pkt_free(pktin);
	return handle;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return NULL;
    }
}

/*
 * Open a directory.
 */
struct fxp_handle *fxp_opendir(char *path)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_OPENDIR);
    sftp_pkt_adduint32(pktout, 0x456); /* request id */
    sftp_pkt_addstring(pktout, path);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return NULL;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x456) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return NULL;
    }
    if (pktin->type == SSH_FXP_HANDLE) {
	char *hstring;
	struct fxp_handle *handle;
	int len;

	sftp_pkt_getstring(pktin, &hstring, &len);
	if (!hstring) {
	    fxp_internal_error("OPENDIR returned malformed FXP_HANDLE\n");
            sftp_pkt_free(pktin);
	    return NULL;
	}
	if((handle = malloc(sizeof(struct fxp_handle))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	handle->hstring = mkstr(hstring, len);
	handle->hlen = len;
	sftp_pkt_free(pktin);
	return handle;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return NULL;
    }
}

/*
 * Close a file/dir.
 */
void fxp_close(struct fxp_handle *handle)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_CLOSE);
    sftp_pkt_adduint32(pktout, 0x789); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x789) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return;
    }
    fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    free(handle->hstring);
    free(handle);
}

int fxp_mkdir(char *path)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_MKDIR);
    sftp_pkt_adduint32(pktout, 0x234); /* request id */
    sftp_pkt_addstring(pktout, path);
    sftp_pkt_adduint32(pktout, 0);     /* (FIXME) empty ATTRS structure */
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x234) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}

int fxp_rmdir(char *path)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_RMDIR);
    sftp_pkt_adduint32(pktout, 0x345); /* request id */
    sftp_pkt_addstring(pktout, path);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x345) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}

int fxp_remove(char *fname)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_REMOVE);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring(pktout, fname);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}

int fxp_rename(char *srcfname, char *dstfname)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_RENAME);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring(pktout, srcfname);
    sftp_pkt_addstring(pktout, dstfname);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}

/*
 * Retrieve the attributes of a file. We have fxp_stat which works
 * on filenames, and fxp_fstat which works on open file handles.
 */
int fxp_stat(char *fname, struct fxp_attrs *attrs)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_STAT);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring(pktout, fname);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }

    if (pktin->type == SSH_FXP_ATTRS) {
	*attrs = sftp_pkt_getattrs(pktin);
        sftp_pkt_free(pktin);
	return 1;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return 0;
    }
}

int fxp_fstat(struct fxp_handle *handle, struct fxp_attrs *attrs)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_FSTAT);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }

    if (pktin->type == SSH_FXP_ATTRS) {
	*attrs = sftp_pkt_getattrs(pktin);
        sftp_pkt_free(pktin);
	return 1;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return 0;
    }
}

/*
 * Set the attributes of a file.
 */
int fxp_setstat(char *fname, struct fxp_attrs attrs)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_SETSTAT);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring(pktout, fname);
    sftp_pkt_addattrs(pktout, attrs);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}
int fxp_fsetstat(struct fxp_handle *handle, struct fxp_attrs attrs)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_FSETSTAT);
    sftp_pkt_adduint32(pktout, 0x678); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_pkt_addattrs(pktout, attrs);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0x678) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    id = fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    if (id != 1) {
    	return 0;
    }
    return 1;
}

/*
 * Read from a file. Returns the number of bytes read, or -1 on an
 * error, or possibly 0 if EOF. (I'm not entirely sure whether it
 * will return 0 on EOF, or return -1 and store SSH_FX_EOF in the
 * error indicator. It might even depend on the SFTP server.)
 */
int fxp_read(struct fxp_handle *handle, char *buffer, uint64 offset,
	     int len)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_READ);
    sftp_pkt_adduint32(pktout, 0xBCD); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_pkt_adduint64(pktout, offset);
    sftp_pkt_adduint32(pktout, len);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return -1;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0xBCD) {
	fxp_internal_error("request ID mismatch");
        sftp_pkt_free(pktin);
	return -1;
    }
    if (pktin->type == SSH_FXP_DATA) {
	char *str;
	int rlen;

	sftp_pkt_getstring(pktin, &str, &rlen);

	if (rlen > len || rlen < 0) {
	    fxp_internal_error("READ returned more bytes than requested");
            sftp_pkt_free(pktin);
	    return -1;
	}

	memcpy(buffer, str, rlen);
        sftp_pkt_free(pktin);
	return rlen;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return -1;
    }
}

/*
 * Read from a directory.
 */
struct fxp_names *fxp_readdir(struct fxp_handle *handle)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_READDIR);
    sftp_pkt_adduint32(pktout, 0xABC); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return NULL;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0xABC) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return NULL;
    }
    if (pktin->type == SSH_FXP_NAME) {
	struct fxp_names *ret;
	int i;
	if((ret = malloc(sizeof(struct fxp_names))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	ret->nnames = sftp_pkt_getuint32(pktin);
	if((ret->names = malloc(ret->nnames * sizeof(struct fxp_name))) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	for (i = 0; i < ret->nnames; i++) {
	    char *str;
	    int len;
	    sftp_pkt_getstring(pktin, &str, &len);
	    ret->names[i].filename = mkstr(str, len);
	    sftp_pkt_getstring(pktin, &str, &len);
	    ret->names[i].longname = mkstr(str, len);
	    ret->names[i].attrs = sftp_pkt_getattrs(pktin);
	}
        sftp_pkt_free(pktin);
	return ret;
    } else {
	fxp_got_status(pktin);
        sftp_pkt_free(pktin);
	return NULL;
    }
}

/*
 * Write to a file. Returns 0 on error, 1 on OK.
 */
int fxp_write(struct fxp_handle *handle, char *buffer, uint64 offset,
	      int len)
{
    struct sftp_packet *pktin, *pktout;
    int id;

    pktout = sftp_pkt_init(SSH_FXP_WRITE);
    sftp_pkt_adduint32(pktout, 0xDCB); /* request id */
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, handle->hstring, handle->hlen);
    sftp_pkt_adduint64(pktout, offset);
    sftp_pkt_addstring_start(pktout);
    sftp_pkt_addstring_data(pktout, buffer, len);
    sftp_send(pktout);
    pktin = sftp_recv();
    if (!pktin) {
	fxp_internal_error("did not receive a valid SFTP packet\n");
	return 0;
    }
    id = sftp_pkt_getuint32(pktin);
    if (id != 0xDCB) {
	fxp_internal_error("request ID mismatch\n");
        sftp_pkt_free(pktin);
	return 0;
    }
    fxp_got_status(pktin);
    sftp_pkt_free(pktin);
    return fxp_errtype == SSH_FX_OK;
}

/*
 * Free up an fxp_names structure.
 */
void fxp_free_names(struct fxp_names *names)
{
    int i;

    for (i = 0; i < names->nnames; i++) {
	free(names->names[i].filename);
	free(names->names[i].longname);
    }
    free(names->names);
    free(names);
}

/*
 * Duplicate an fxp_name structure.
 */
struct fxp_name *fxp_dup_name(struct fxp_name *name)
{
    struct fxp_name *ret;
    if((ret = malloc(sizeof(struct fxp_name))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    ret->filename = strdup(name->filename);
    ret->longname = strdup(name->longname);
    ret->attrs = name->attrs;	       /* structure copy */
    return ret;
}

/*
 * Free up an fxp_name structure.
 */
void fxp_free_name(struct fxp_name *name)
{
    free(name->filename);
    free(name->longname);
    free(name);
}
