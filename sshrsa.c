/*
 * RSA implementation just sufficient for ssh client-side
 * initialisation step
 *
 * Rewritten for more speed by Joris van Rantwijk, Jun 1999.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "ssh.h"
#include "sshsha.h"
#include "macros.h"
#include "pubkey.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

extern Bignum One;
extern struct ssh2_userkey ssh2_wrong_passphrase;

struct RSAKey {
    int bits;
    int bytes;
    Bignum modulus;
    Bignum exponent;
    Bignum private_exponent;
    Bignum p;
    Bignum q;
    Bignum iqmp;
    char *comment;
};

/*
 * Verify that the public data in an RSA key matches the private
 * data. We also check the private data itself: we ensure that p >
 * q and that iqmp really is the inverse of q mod p.
 */
int rsa_verify(struct RSAKey *key)
{
    Bignum n, ed, pm1, qm1;
    int cmp;

    /* n must equal pq. */
    n = bigmul(key->p, key->q);
    cmp = bignum_cmp(n, key->modulus);
    freebn(n);
    if (cmp != 0)
	return 0;

    /* e * d must be congruent to 1, modulo (p-1) and modulo (q-1). */
    pm1 = copybn(key->p);
    decbn(pm1);
    ed = modmul(key->exponent, key->private_exponent, pm1);
    cmp = bignum_cmp(ed, One);
    free(ed);
    if (cmp != 0)
	return 0;

    qm1 = copybn(key->q);
    decbn(qm1);
    ed = modmul(key->exponent, key->private_exponent, qm1);
    cmp = bignum_cmp(ed, One);
    free(ed);
    if (cmp != 0)
	return 0;

    /*
     * Ensure p > q.
     */
    if (bignum_cmp(key->p, key->q) <= 0)
	return 0;

    /*
     * Ensure iqmp * q is congruent to 1, modulo p.
     */
    n = modmul(key->iqmp, key->q, key->p);
    cmp = bignum_cmp(n, One);
    free(n);
    if (cmp != 0)
	return 0;

    return 1;
}

void freersakey(struct RSAKey *key)
{
    if (key->modulus)
	freebn(key->modulus);
    if (key->exponent)
	freebn(key->exponent);
    if (key->private_exponent)
	freebn(key->private_exponent);
    if (key->comment)
	free(key->comment);
}

/* ----------------------------------------------------------------------
 * Implementation of the ssh-rsa signing key type. 
 */

static void getstring(char **data, int *datalen, char **p, int *length)
{
    *p = NULL;
    if (*datalen < 4)
	return;
    *length = GET_32BIT_MSB_FIRST(*data);
    *datalen -= 4;
    *data += 4;
    if (*datalen < *length)
	return;
    *p = *data;
    *data += *length;
    *datalen -= *length;
}
static Bignum getmp(char **data, int *datalen)
{
    char *p;
    int length;
    Bignum b;

    getstring(data, datalen, &p, &length);
    if (!p)
	return NULL;
    b = bignum_from_bytes(p, length);
    return b;
}

static void *rsa2_newkey(char *data, int len)
{
    char *p;
    int slen;
    struct RSAKey *rsa;

    if((rsa = malloc(sizeof(struct RSAKey))) == NULL)
       fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    getstring(&data, &len, &p, &slen);

    if (!p || slen != 7 || memcmp(p, "ssh-rsa", 7)) {
	free(rsa);
	return NULL;
    }
    rsa->exponent = getmp(&data, &len);
    rsa->modulus = getmp(&data, &len);
    rsa->private_exponent = NULL;
    rsa->comment = NULL;

    return rsa;
}

static void rsa2_freekey(void *key)
{
    struct RSAKey *rsa = (struct RSAKey *) key;
    freersakey(rsa);
    free(rsa);
}

static unsigned char *rsa2_public_blob(void *key, int *len)
{
    struct RSAKey *rsa = (struct RSAKey *) key;
    int elen, mlen, bloblen;
    int i;
    unsigned char *blob, *p;

    elen = (bignum_bitcount(rsa->exponent) + 8) / 8;
    mlen = (bignum_bitcount(rsa->modulus) + 8) / 8;

    /*
     * string "ssh-rsa", mpint exp, mpint mod. Total 19+elen+mlen.
     * (three length fields, 12+7=19).
     */
    bloblen = 19 + elen + mlen;
    if((blob = malloc(bloblen)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    p = blob;
    PUT_32BIT_MSB_FIRST(p, 7);
    p += 4;
    memcpy(p, "ssh-rsa", 7);
    p += 7;
    PUT_32BIT_MSB_FIRST(p, elen);
    p += 4;
    for (i = elen; i--;)
	*p++ = bignum_byte(rsa->exponent, i);
    PUT_32BIT_MSB_FIRST(p, mlen);
    p += 4;
    for (i = mlen; i--;)
	*p++ = bignum_byte(rsa->modulus, i);
    assert(p == blob + bloblen);
    *len = bloblen;
    return blob;
}

static void *rsa2_createkey(unsigned char *pub_blob, int pub_len,
			    unsigned char *priv_blob, int priv_len)
{
    struct RSAKey *rsa;
    char *pb = (char *) priv_blob;

    rsa = rsa2_newkey((char *) pub_blob, pub_len);
    rsa->private_exponent = getmp(&pb, &priv_len);
    rsa->p = getmp(&pb, &priv_len);
    rsa->q = getmp(&pb, &priv_len);
    rsa->iqmp = getmp(&pb, &priv_len);

    if (!rsa_verify(rsa)) {
	rsa2_freekey(rsa);
	return NULL;
    }

    return rsa;
}

/*
 * This is the magic ASN.1/DER prefix that goes in the decoded
 * signature, between the string of FFs and the actual SHA hash
 * value. The meaning of it is:
 * 
 * 00 -- this marks the end of the FFs; not part of the ASN.1 bit itself
 * 
 * 30 21 -- a constructed SEQUENCE of length 0x21
 *    30 09 -- a constructed sub-SEQUENCE of length 9
 *       06 05 -- an object identifier, length 5
 *          2B 0E 03 02 1A -- object id { 1 3 14 3 2 26 }
 *                            (the 1,3 comes from 0x2B = 43 = 40*1+3)
 *       05 00 -- NULL
 *    04 14 -- a primitive OCTET STRING of length 0x14
 *       [0x14 bytes of hash data follows]
 * 
 * The object id in the middle there is listed as `id-sha1' in
 * ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1d2.asn (the
 * ASN module for PKCS #1) and its expanded form is as follows:
 * 
 * id-sha1                OBJECT IDENTIFIER ::= {
 *    iso(1) identified-organization(3) oiw(14) secsig(3)
 *    algorithms(2) 26 }
 */
static unsigned char asn1_weird_stuff[] = {
    0x00, 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B,
    0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14,
};

#define ASN1_LEN ( (int) sizeof(asn1_weird_stuff) )

unsigned char *rsa2_sign(void *key, char *data, int datalen, int *siglen)
{
    struct RSAKey *rsa = (struct RSAKey *) key;
    unsigned char *bytes;
    int nbytes;
    unsigned char hash[20];
    Bignum in, out;
    int i, j;

    SHA_Simple(data, datalen, hash);

    nbytes = (bignum_bitcount(rsa->modulus) - 1) / 8;
    if((bytes = malloc(nbytes)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

    bytes[0] = 1;
    for (i = 1; i < nbytes - 20 - ASN1_LEN; i++)
	bytes[i] = 0xFF;
    for (i = nbytes - 20 - ASN1_LEN, j = 0; i < nbytes - 20; i++, j++)
	bytes[i] = asn1_weird_stuff[j];
    for (i = nbytes - 20, j = 0; i < nbytes; i++, j++)
	bytes[i] = hash[j];

    in = bignum_from_bytes(bytes, nbytes);
    free(bytes);

    out = modpow(in, rsa->private_exponent, rsa->modulus);
    freebn(in);

    nbytes = (bignum_bitcount(out) + 7) / 8;
    if((bytes = malloc(4 + 7 + 4 + nbytes)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    PUT_32BIT_MSB_FIRST(bytes, 7);
    memcpy(bytes + 4, "ssh-rsa", 7);
    PUT_32BIT_MSB_FIRST(bytes + 4 + 7, nbytes);
    for (i = 0; i < nbytes; i++)
	bytes[4 + 7 + 4 + i] = bignum_byte(out, nbytes - 1 - i);
    freebn(out);

    *siglen = 4 + 7 + 4 + nbytes;
    return bytes;
}

const struct ssh_signkey ssh_rsa = {
    rsa2_public_blob,
    rsa2_createkey,
    rsa2_sign,
    "ssh-rsa",
};
