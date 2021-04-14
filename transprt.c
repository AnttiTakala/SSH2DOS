/* transprt.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2006/02/26 18:05:16 $
 * $Revision: 1.11 $
 *
 * This module is the SSH2 transport layer.
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
#include <conio.h>
#include <string.h>

#include "zlib.h"

#include "tcp.h"
#include "sshbn.h"
#include "config.h"
#include "common.h"
#include "macros.h"
#include "sshsha.h"
#include "ssh.h"
#include "transprt.h"
#include "keyio.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

/* cipher functions */
void aes_csiv(unsigned char *);
void aes128_cskey(unsigned char *);
void aes_sciv(unsigned char *);
void aes128_sckey(unsigned char *);
void aes_ssh2_encrypt_blk(unsigned char *, unsigned long);
void aes_ssh2_decrypt_blk(unsigned char *, unsigned long);

/* external data */
extern Config GlobalConfig;		/* global configuration structure */
extern unsigned short Configuration;	/* Configuration bits */
extern SHA_State exhashbase;
extern Bignum One;

/* global data */
Packet pktin = { 0, 0, 0, NULL, NULL, NULL };/* incoming SSH2 packet */
Packet pktout = { 0, 0, 0, NULL, NULL, NULL };/* outgoing SSH2 packet */
unsigned char ssh2_session_id[20];		/* Session identifier */
char *RemoteClosed = "Remote host closed connection";
char *ConnectionClosed = "Connection closed";
char *protocolerror = "Protocol error";

/*
 * Local static data
 */
static unsigned long incoming_sequence;	/* incoming packet number */
static unsigned long outgoing_sequence;	/* outgoing packet number */
static unsigned short MACLength;	/* MAC length */
static unsigned short first_kex;	/* First key exchange? */
static SHA_State exhash;		     /* SHA hash after string excange */

static z_stream comp;			     /* compression stream */
static z_stream decomp;			     /* decompression stream */

/* The prime p used in the DH key exchange. */
static unsigned char P[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static Bignum x, p, q, qmask, g;     /* Variables for Diffie-Hellaman */

/*
 * Save packets in hexadecimal format for debugging purposes
 */
static void fwritehex(unsigned char *dbgbuf, unsigned short length)
{
unsigned short i;

   for(i = 1; i <= length; i++){ /* print hexa dump first */
	fprintf(GlobalConfig.debugfile, "%02X ", *dbgbuf++);
	if(i%16 == 0) /* 16 bytes per row */
	   fputs("\n", GlobalConfig.debugfile);
   }

   fputs("\n", GlobalConfig.debugfile);
   dbgbuf-=length;

   for(i = 1; i <= length; i++){ /* now print raw data */
	if(*dbgbuf >= ' ' && *dbgbuf < 126)
	   fprintf(GlobalConfig.debugfile, "%c", *dbgbuf);
	else                    /* put '.' instead of non-readable bytes */
	   fputc('.', GlobalConfig.debugfile);
	if(i%16==0)
	    fputs("\n", GlobalConfig.debugfile);
	dbgbuf++;
   }

}


static Bignum SSH_getmp(void)
{
char *p;
unsigned long length;
Bignum b;

   SSH_getstring(&p, &length);
   if(!p)
	return NULL;
   b = bignum_from_bytes(p, length);
   return b;
}


/*
 * Initialize important variables
 */
void SSH2_init(void)
{
   incoming_sequence = 0;
   outgoing_sequence = 0;
   MACLength = 0;
   first_kex = 1;
}

/*
 * Common DH initialisation.
 */
static void dh_init(void)
{
   q = bignum_rshift(p, 1);
   qmask = bignum_bitmask(q);
}


static void sha_uint32(SHA_State * s, unsigned long i)
{
    unsigned char intblk[4];
    PUT_32BIT_MSB_FIRST(intblk, i);
    SHA_Bytes(s, intblk, 4);
}


/*
 * Initialise DH for the standard group1.
 */
static void dh_setup_group1(void)
{
unsigned char G[] = { 2 };

   p = bignum_from_bytes(P, sizeof(P));
   g = bignum_from_bytes(G, sizeof(G));
   dh_init();
}


/*
 * Initialise DH for an alternative group.
 */
static void dh_setup_group(Bignum pval, Bignum gval)
{
    p = copybn(pval);
    g = copybn(gval);
    dh_init();
}


/*
 * Clean up.
 */
static void dh_cleanup(void)
{
   freebn(x);
   freebn(p);
   freebn(g);
   freebn(q);
   freebn(qmask);
}

/*
 * DH stage 1: invent a number x between 1 and q, and compute e =
 * g^x mod p. Return e.
 * 
 * If `nbits' is greater than zero, it is used as an upper limit
 * for the number of bits in x. This is safe provided that (a) you
 * use twice as many bits in x as the number of bits you expect to
 * use in your session key, and (b) the DH group is a safe prime
 * (which SSH demands that it must be).
 * 
 * P. C. van Oorschot, M. J. Wiener
 * "On Diffie-Hellman Key Agreement with Short Exponents".
 * Advances in Cryptology: Proceedings of Eurocrypt '96
 * Springer-Verlag, May 1996.
 */
static Bignum dh_create_e(unsigned short nbits)
{
unsigned short i, b;
short nb;
unsigned short nbytes;
unsigned char *buf;
Bignum e;

   nbytes = ssh1_bignum_length(qmask);
   if((buf = malloc(nbytes)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

   do {
	/*
	 * Create a potential x, by ANDing a string of random bytes
	 * with qmask.
	 */
	if (x)
	    freebn(x);
	if (nbits == 0 || nbits > bignum_bitcount(qmask)) {
	    ssh1_write_bignum(buf, qmask);
	    for (i = 2; i < nbytes; i++)
		buf[i] &= rand() % 256;
	    ssh1_read_bignum(buf, &x);
	} else {
	    x = bn_power_2(nbits);
	    b = nb = 0;
	    for (i = 0; i < nbits; i++) {
		if (nb == 0) {
		    nb = 8;
		    b = rand() % 256;
		}
		bignum_set_bit(x, i, b & 1);
		b >>= 1;
		nb--;
	    }
	}
   } while (bignum_cmp(x, One) <= 0 || bignum_cmp(x, q) >= 0);

   free(buf);

   /*
    * Done. Now compute e = g^x mod p.
    */
   e = modpow(g, x, p);

   return e;
}

/*
 * DH stage 2: given a number f, compute K = f^x mod p.
 */
static Bignum dh_find_K(Bignum f)
{
Bignum ret;

   ret = modpow(f, x, p);
   return ret;
}

/*
 * SSH2 key creation method.
 */
static void ssh2_mkkey(Bignum K, char *H, char *sessid, char chr,
		       char *keyspace)
{
SHA_State s;

    /* First 20 bytes. */
    SHA_Init(&s);
    sha_mpint(&s, K);
    SHA_Bytes(&s, H, 20);
    SHA_Bytes(&s, &chr, 1);
    SHA_Bytes(&s, sessid, 20);
    SHA_Final(&s, keyspace);
    /* Next 20 bytes. */
    SHA_Init(&s);
    sha_mpint(&s, K);
    SHA_Bytes(&s, H, 20);
    SHA_Bytes(&s, keyspace, 20);
    SHA_Final(&s, keyspace + 20);
}

/*
 * SSH2 key exchange. List our supported algorithms, construct
 * and send the packed. Wait for the server key exchange packet
 */
static void SSH2_KexInit(void)
{
unsigned short i;
unsigned char cookie[16];

   /* Create cookie */
   for (i = 0; i < 16; i++)
	cookie[i] = rand() % 256;

   SSH_pkt_init(SSH_MSG_KEXINIT);
   SSH_putdata(cookie, 16); 
   if(Configuration & DHGROUP)
      SSH_putstring("diffie-hellman-group-exchange-sha1"); 
   else
      SSH_putstring("diffie-hellman-group1-sha1"); 
   SSH_putstring("ssh-dss");
   SSH_putstring("aes128-cbc"); 
   SSH_putstring("aes128-cbc"); 
   SSH_putstring("hmac-sha1"); 
   SSH_putstring("hmac-sha1"); 
   if(Configuration & COMPRESSION_REQUESTED){
        SSH_putstring("zlib,none"); 
        SSH_putstring("zlib,none"); 
   }
   else{
        SSH_putstring("none,zlib"); 
        SSH_putstring("none,zlib"); 
   }
   SSH_putuint32(0); 
   SSH_putuint32(0); 
   SSH_putbool(0); 
   SSH_putuint32(0); 

   /* Mix this to the Diffie-Hellman key exchange */
   exhash = exhashbase;
   sha_string(&exhash, pktout.body, pktout.length);

   /* Mix host packet to the Diffie-Hellman key exchange */
   sha_string(&exhash, pktin.body, pktin.length);

   if(Configuration & VERBOSE_MODE)
        puts("Sending our key exchange packet");
   SSH_pkt_send();
}

/*
 * The Diffie-Hellman key exchange. We already hashed the
 * needed values (version strings, key exchange packets).
 * This is also used in key re-exchange, so we must know if
 * it's the initial or a re-exchange.
 */
static short SSH2_DHExchange(void)
{
Bignum e, f, K;
char *hostkeydata;
unsigned long hostkeylen;
unsigned char keyspace[40];
unsigned char exchange_hash[20];
int kexinit, kexreply;

   /* Initiate our key exchange */
   SSH2_KexInit();

   if(Configuration & DHGROUP){
      SSH_pkt_init(SSH_MSG_KEX_DH_GEX_REQUEST);
      SSH_putuint32(1024);
      if((Configuration & VERBOSE_MODE) && first_kex)
         puts("Diffie-Hellman group key exchange");
      SSH_pkt_send();
      if(SSH_pkt_read(NULL))
         return(1);
      if(pktin.type != SSH_MSG_KEX_DH_GEX_GROUP){
	 SSH_Disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Expected KEX_DH_GEX_GROUP");
	 return(1);
      }
      p = SSH_getmp();
      g = SSH_getmp();
      dh_setup_group(p, g);
      kexinit = SSH_MSG_KEX_DH_GEX_INIT;
      kexreply = SSH_MSG_KEX_DH_GEX_REPLY;
   } else {
      if((Configuration & VERBOSE_MODE) && first_kex)
         puts("Diffie-Hellman key exchange");
      dh_setup_group1();
      kexinit = SSH_MSG_KEXDH_INIT;
      kexreply = SSH_MSG_KEXDH_REPLY;
   }
   e = dh_create_e(128 * 2);

   SSH_pkt_init(kexinit);
   SSH_putmp(e);
   SSH_pkt_send();

   if(SSH_pkt_read(NULL))
        return(1);
   if(pktin.type != kexreply){
	SSH_Disconnect(SSH_DISCONNECT_KEY_EXCHANGE_FAILED, "Expected kex reply");
	return(1);
   }

   SSH_getstring(&hostkeydata, &hostkeylen);
   f = SSH_getmp();
   K = dh_find_K(f);

   sha_string(&exhash, hostkeydata, hostkeylen);
   if(Configuration & DHGROUP){
      sha_uint32(&exhash, 1024);
      sha_mpint(&exhash, p);
      sha_mpint(&exhash, g);
   }
   sha_mpint(&exhash, e);
   sha_mpint(&exhash, f);
   sha_mpint(&exhash, K);
   SHA_Final(&exhash, exchange_hash);

   dh_cleanup();
   freebn(e);
   freebn(f);

   /* Send SSH_MSG_NEWKEYS */
   if((Configuration & VERBOSE_MODE) && first_kex)
        puts("Start using agreed keys");
   SSH_pkt_init(SSH_MSG_NEWKEYS);
   SSH_pkt_send();

   /* Expect SSH_MSG_NEWKEYS from server */
   if((Configuration & VERBOSE_MODE) && first_kex)
        puts("Waiting for host ACK");
   if(SSH_pkt_read(SSH_MSG_NEWKEYS)){
	puts("Didn't receive NEWKEYS ACK");
	return(1);
   }

   /*
    * Set IVs after keys. Here we use the exchange hash from the
    * _first_ key exchange.
    */
   if((Configuration & VERBOSE_MODE) && first_kex)
	puts("Initializing encryption and hash functions");
   if(first_kex)
	memcpy(ssh2_session_id, exchange_hash, sizeof(exchange_hash));
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'A', keyspace);
   aes_csiv(keyspace);
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'B', keyspace);
   aes_sciv(keyspace);
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'C', keyspace);
   aes128_cskey(keyspace);
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'D', keyspace);
   aes128_sckey(keyspace);
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'E', keyspace);
   sha1_cskey(keyspace);
   ssh2_mkkey(K, exchange_hash, ssh2_session_id, 'F', keyspace);
   sha1_sckey(keyspace);
   freebn(K);

   return(0);
}

/*
 * Compress a packet
 */
static void SSH_Compress(const Bytef*source, uLong sourceLen,
		Bytef**dest, uLong *destLen)
{
   if((*dest = (char *)malloc(*destLen)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   comp.next_in = (Bytef*)source;	/* source buffer */
   comp.avail_in = (uInt)sourceLen;	/* source length */
   comp.next_out = *dest;		/* destination buffer */
   comp.avail_out = *destLen;		/* max destination length */

   if(deflate(&comp, Z_SYNC_FLUSH) != Z_OK){
        SSH_Disconnect(SSH_DISCONNECT_COMPRESSION_ERROR, "Compression error");
        fatal("Line: %u", __LINE__);
   }

   if(comp.avail_out == 0){ /* FIXME: compression buffer is too small */
        SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "");
	fatal("Compression buffer is too small. Line: %u", __LINE__);
   }
   *destLen = *destLen - comp.avail_out;
}

/*
 * Uncompress a packet We enlarge the decompression buffer as
 * needed.
 */
static void SSH_Uncompress(const Bytef*source, uLong sourceLen,
		  Bytef **dest, uLongf *destLen)
{
int n, m;

   *destLen = 512;
   if((*dest = (char *)malloc(*destLen)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   decomp.next_in = (Bytef*)source;	/* source buffer */
   decomp.avail_in = (uInt)sourceLen;	/* source length */
   decomp.avail_out = 512;

   for(n = 0; ; n++, decomp.avail_out = 512){
      decomp.next_out = *dest + n * 512;  /* destination buffer */
      if((m = inflate(&decomp, Z_SYNC_FLUSH)) != Z_OK){
        SSH_Disconnect(SSH_DISCONNECT_COMPRESSION_ERROR, "Decompression error");
        fatal("Line: %u", __LINE__);
      }
      *destLen -= decomp.avail_out;
      if(decomp.avail_out)		  /* end if no more input data */
         break;
      *destLen += 512;
      if((*dest = (char *)realloc(*dest, *destLen)) == NULL)
         fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   }
}

/*
 * Free compression structures
 */
void Disable_Compression(void)
{
   deflateEnd(&comp);
   inflateEnd(&decomp);
}


/*
 * Request compression
 */
void Request_Compression(int level)
{
   if(Configuration & VERBOSE_MODE)
	puts("Requesting compression");

   memset(&comp, 0, sizeof(comp));
   memset(&decomp, 0, sizeof(decomp));
   if(deflateInit(&comp, level) != Z_OK){
	SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "");
	fatal("Cannot initialize compression. Line: %u", __LINE__);
   }
   if(inflateInit(&decomp) != Z_OK){
	SSH_Disconnect(SSH_DISCONNECT_BY_APPLICATION, "");
	fatal("Cannot initialize decompression. Line: %u", __LINE__);
   }
   Configuration |= COMPRESSION_ENABLED;
}

/*
 * Calculate full packet length from given length
 * and reallocate memory
 */
static void SSH2_pkt_size(unsigned long len)
{
unsigned short pad;
unsigned long PktLength;

   pktout.length = len;
   len += 5;			/* add length and padlength fields */
   pad = 32 - (len%16);		/* calculate padding */
   PktLength = len + pad + MACLength;	/* add padding and MAC */
   if((pktout.whole = realloc(pktout.whole, PktLength)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   pktout.body = pktout.whole + 5;
}

/*
 * Enlarge outgoing packet if needed
 */
static void SSH2_pkt_grow(unsigned long len)
{
   pktout.length += len;
   if(pktout.length > pktout.maxlen){
	pktout.maxlen = pktout.length + 256;
	if((pktout.whole = realloc(pktout.whole, pktout.maxlen)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	pktout.body = pktout.whole + 5;
	pktout.ptr = pktout.body + pktout.length - len;
   }
}

/*
 * Initialize an outgoing SSH2 packet.
 */
void SSH_pkt_init(unsigned char type)
{
   pktout.length = 1;		/* We only have the type now */
   pktout.maxlen = 1024;	/* Seems good size to start a packet */
   if((pktout.whole = malloc(pktout.maxlen)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   pktout.body = pktout.whole + 5;
   pktout.ptr = pktout.body + 1;
   *pktout.body = type;
}

/*
 * SSH2 packet assembly functions. These can put multiple
 * types of data into an SSH2 packet
 */
void SSH_putdata(unsigned char *data, unsigned short len)
{
   SSH2_pkt_grow(len);
   memcpy(pktout.ptr, data, len);
   pktout.ptr += len;
}

void SSH_putbool(unsigned char value)
{
   SSH_putdata(&value, 1);
}

void SSH_putuint32(unsigned long value)
{
unsigned char x[4];

   PUT_32BIT_MSB_FIRST(x, value);
   SSH_putdata(x, 4);
}

void SSH_putstring(unsigned char *str)
{
   SSH_putuint32(strlen(str));
   SSH_putdata(str, strlen(str));
}

unsigned short SSH_putmp(Bignum b)
{
unsigned char *p;
unsigned long len;

   p = ssh2_mpint_fmt(b, &len);
   SSH_putuint32(len);
   SSH_putdata(p, len);
   free(p);
   return(len);
}

/*
 * Assemble and send a raw SSH2 packet
 */
void SSH_pkt_send(void)
{
int i, PadLength;
unsigned long PktLength;
unsigned short len;
unsigned char *compblk;
unsigned long complen;

/*
1. Fill data
2. Compress (data)
3. Calculate and add padding
4. Calculate length (n + pl + 1)
5. Calculate MAC (from whole packet)
6. Encrypt (all minus MAC)
7. Send
*/

   if(GlobalConfig.debugfile){
	fputs("\nSENT packet:\n", GlobalConfig.debugfile);
	fwritehex(pktout.body, pktout.length);
	fputc('\n', GlobalConfig.debugfile);
   }

   if(Configuration & COMPRESSION_ENABLED){
	complen = (pktout.length + 13) * 11 / 10 + 1;
        SSH_Compress(pktout.body, pktout.length, &compblk, &complen);
	SSH2_pkt_size(complen);
	memcpy(pktout.body, compblk, complen);
	free(compblk);
   } /* Compression */
   else
	SSH2_pkt_size(pktout.length);

   len = pktout.length + 5;	       /* plus length and padlength fields*/
   PadLength = 32 - (len%16);
   PktLength = len + PadLength;

   for (i = 0; i < PadLength; i++)
	pktout.whole[i + len] = rand() % 256;

   PUT_32BIT_MSB_FIRST(pktout.whole, PktLength - 4);
   pktout.whole[4] = PadLength;

   if(MACLength)
	sha1_generate(pktout.whole, PktLength, outgoing_sequence);
   outgoing_sequence++;	       /* whether or not we MACed */

   PktLength += MACLength;

   if(Configuration & CIPHER_ENABLED)
	aes_ssh2_encrypt_blk(pktout.whole, PktLength - MACLength);

   sock_flushnext(&GlobalConfig.s);
   if(sock_write(&GlobalConfig.s, pktout.whole, PktLength) != PktLength)
	fatal("Socket write error. File: %s, line: %u", __FILE__, __LINE__);
   free(pktout.whole);
}

/*
 * Read and convert raw packet to readable structure.
 * Uncrypt and uncompress if necessary
 */
static short ssh_gotdata(void)
{
unsigned long len;
unsigned long PktLength;	/* full packet length */
unsigned char PktInLength[16];	/* first 16 bytes of a packet */
unsigned char *inbuf;           /* buffer for incoming packet */
unsigned char *decompblk;	/* buffer for decompression */

/*
1. Read 16 bytes
2. Decrypt and get length (data + pad + 1)
3. Read full packet
4. Decrypt rest of packet
5. Verify MAC
6. Uncompress (data)
7. Handle according to type
*/

   if(sock_read(&GlobalConfig.s, PktInLength, 16) != 16)
      fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);

   if(Configuration & CIPHER_ENABLED)
	aes_ssh2_decrypt_blk(PktInLength, 16);

   len = GET_32BIT_MSB_FIRST(PktInLength);	/* get length */
   pktin.length = len - PktInLength[4] - 1;	/* get useful data length */
   PktLength = len + 4 + MACLength;		/* full packet length */
   if(PktLength > MAX_PACKET_SIZE + 256){	/* allow frame overhead */
      fatal("Too large packet received. File: %s, line: %u", __FILE__, __LINE__);
   }

   if((inbuf = malloc(PktLength)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   memcpy(inbuf, PktInLength, 16); /* copy already read part first */
   if(sock_read(&GlobalConfig.s, inbuf + 16, PktLength - 16) != PktLength - 16) /* Read rest */
      fatal("Socket read error. File: %s, line: %u", __FILE__, __LINE__);

   if(Configuration & CIPHER_ENABLED) /* uncrypt */
	aes_ssh2_decrypt_blk(inbuf + 16, PktLength - 16 - MACLength);

   if(MACLength) /* verify MAC if present */
        if(!sha1_verify(inbuf, len + 4, incoming_sequence)){
           SSH_Disconnect(SSH_DISCONNECT_MAC_ERROR, "Incorrect MAC received");
	   free(inbuf);
           return(1);
        }
   incoming_sequence++;

   if((pktin.body = (pktin.body == NULL ? malloc(pktin.length) :
			realloc(pktin.body, pktin.length))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   memcpy(pktin.body, inbuf + 5, pktin.length);
   free(inbuf); /* it's now in pktin structure, so free it */

   if(Configuration & COMPRESSION_ENABLED){
	len = (10 * pktin.length < (MAX_PACKET_SIZE + 256) * 2) ?
			 (MAX_PACKET_SIZE + 256) * 2 : 10 * pktin.length;
        SSH_Uncompress(pktin.body, pktin.length, &decompblk, &len);
	if((pktin.body = realloc(pktin.body, len)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	memcpy(pktin.body, decompblk, len); /* copy uncompressed */
	free(decompblk);
	pktin.length = len;
    } /* Compression */

   if(GlobalConfig.debugfile){
	fputs("\nRECEIVED packet:\n", GlobalConfig.debugfile);
	fwritehex(pktin.body, pktin.length);
	fputc('\n', GlobalConfig.debugfile);
   } /* debug */

   pktin.type = *pktin.body;
   pktin.ptr = pktin.body + 1;
   return(0);
}

/*
 * Get a packet with blocking. Handle debug, ignore and disconnect packets.
 * If type != NULL, also checks type to avoid protocol confusion.
 * Check for user input too.
 *
 * Returns 1 and disconnects if: MAC error occured
 *                               DISCONNECT received
 *	                	 protocol error occured
 *	                	 socket error occured
 */
short SSH_pkt_read(unsigned char type)
{
unsigned long len;
int status;
char *str;

restart:
   while(!sock_dataready(&GlobalConfig.s)){	/* do we got some data? */
        sock_tick(&GlobalConfig.s, &status);	/* TCP wait and 	*/
//        while (ConChk())			/* examine STDIN if not */
//	   DoKey();
   }

   if(ssh_gotdata())
        return(1); /* we got MAC error */

   switch(pktin.type){
        case SSH_MSG_DISCONNECT:
	   pktin.ptr +=4;
           SSH_getstring(&str, &len);
           str[len] = 0;
	   printf("Remote host disconnected: %s\n", str);
	   return(1);

        case SSH_MSG_IGNORE:
	   break;

        case SSH_MSG_DEBUG:
	   if(SSH_getbool()){
        	SSH_getstring(&str, &len);
                str[len] = 0;
        	printf("DEBUG: %s\n", str);
           } /* if */
           goto restart;

	case SSH_MSG_KEXINIT: /* it's a key-exchange */
	   if(SSH2_DHExchange()){
		puts("DH key exchange failed ");
		return(1);
	   }
	   first_kex = 0;
           MACLength = 20;
	   type = SSH_MSG_NEWKEYS; /* this should be the last MSG from host */
           break;

	case SSH_MSG_SERVICE_ACCEPT:
	case SSH_MSG_NEWKEYS:
	case SSH_MSG_KEXDH_INIT:
	case SSH_MSG_KEXDH_REPLY:
	case SSH_MSG_KEX_DH_GEX_INIT:
	case SSH_MSG_KEX_DH_GEX_REPLY:
           break;

        default:
           if(pktin.type < 50){
	        SSH_pkt_init(SSH_MSG_UNIMPLEMENTED);
                SSH_putuint32(incoming_sequence);
                SSH_pkt_send();
           }
           break;

   } /* switch */

   if(type)
	if(pktin.type != type){
	   SSH_Disconnect(SSH_DISCONNECT_PROTOCOL_ERROR, protocolerror);
	   return(1);
	}

   return(0);

sock_err:
   switch (status){
        case 1 :
	   puts(ConnectionClosed);
	   break;

        case -1:
	   puts(RemoteClosed);
	   break;
   }
   return(1);
}

/*
 * SSH2 packet decode functions. These can be used to retrieve
 * formatted data from a SSH packet
 */
unsigned long SSH_getuint32(void)
{
unsigned long value;

   value = GET_32BIT_MSB_FIRST(pktin.ptr);
   pktin.ptr += 4;
   return value;
}

unsigned int SSH_getbool(void)
{
unsigned long value;

   value = *pktin.ptr++;
   return value;
}

void SSH_getstring(char **p, unsigned long *length)
{
   *length = SSH_getuint32();
   *p = pktin.ptr;
   pktin.ptr += *length;
}

/*
 * Disconnect and print error if needed
 */
void SSH_Disconnect(unsigned long errcode, const char *fmt, ...)
{
va_list ap;
char buf[256];

   va_start(ap, fmt);
   vsprintf(buf, fmt, ap);
   va_end(ap);

   if(*buf)
	puts(buf);

   SSH_pkt_init(SSH_MSG_DISCONNECT);
   SSH_putuint32(errcode);
   if(*buf)
	SSH_putstring(buf);
   else
        SSH_putuint32(0);
   SSH_putuint32(0);
   SSH_pkt_send();
}
