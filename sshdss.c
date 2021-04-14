/*
 * DSS key routines
 *
 * Taken from the PuTTY source.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "pubkey.h"
#include "sshsha.h"
#include "ssh.h"
#include "macros.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

extern struct ssh2_userkey ssh2_wrong_passphrase;

struct dss_key {
    Bignum p, q, g, y, x;
};

static void sha_mpint2(SHA_State * s, Bignum b)
{
    unsigned char lenbuf[4];
    int len;
    len = (bignum_bitcount(b) + 8) / 8;
    PUT_32BIT_MSB_FIRST(lenbuf, len);
    SHA_Bytes(s, lenbuf, 4);
    while (len-- > 0) {
	lenbuf[0] = bignum_byte(b, len);
	SHA_Bytes(s, lenbuf, 1);
    }
    memset(lenbuf, 0, sizeof(lenbuf));
}

static void sha512_mpint(SHA512_State * s, Bignum b)
{
    unsigned char lenbuf[4];
    int len;
    len = (bignum_bitcount(b) + 8) / 8;
    PUT_32BIT_MSB_FIRST(lenbuf, len);
    SHA512_Bytes(s, lenbuf, 4);
    while (len-- > 0) {
	lenbuf[0] = bignum_byte(b, len);
	SHA512_Bytes(s, lenbuf, 1);
    }
    memset(lenbuf, 0, sizeof(lenbuf));
}

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
    if (p[0] & 0x80)
	return NULL;		       /* negative mp */
    b = bignum_from_bytes(p, length);
    return b;
}

static void *dss_newkey(char *data, int len)
{
    char *p;
    int slen;
    struct dss_key *dss;

    if((dss = (struct dss_key *)malloc(sizeof(struct dss_key))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    if (!dss)
	return NULL;
    getstring(&data, &len, &p, &slen);

#ifdef DEBUG_DSS
    {
	int i;
	printf("key:");
	for (i = 0; i < len; i++)
	    printf("  %02x", (unsigned char) (data[i]));
	printf("\n");
    }
#endif

    if (!p || memcmp(p, "ssh-dss", 7)) {
	free(dss);
	return NULL;
    }
    dss->p = getmp(&data, &len);
    dss->q = getmp(&data, &len);
    dss->g = getmp(&data, &len);
    dss->y = getmp(&data, &len);

    return dss;
}

static void dss_freekey(void *key)
{
    struct dss_key *dss = (struct dss_key *) key;
    freebn(dss->p);
    freebn(dss->q);
    freebn(dss->g);
    freebn(dss->y);
    free(dss);
}

static unsigned char *dss_public_blob(void *key, int *len)
{
    struct dss_key *dss = (struct dss_key *) key;
    int plen, qlen, glen, ylen, bloblen;
    int i;
    unsigned char *blob, *p;

    plen = (bignum_bitcount(dss->p) + 8) / 8;
    qlen = (bignum_bitcount(dss->q) + 8) / 8;
    glen = (bignum_bitcount(dss->g) + 8) / 8;
    ylen = (bignum_bitcount(dss->y) + 8) / 8;

    /*
     * string "ssh-dss", mpint p, mpint q, mpint g, mpint y. Total
     * 27 + sum of lengths. (five length fields, 20+7=27).
     */
    bloblen = 27 + plen + qlen + glen + ylen;
    if((blob = (unsigned char *)malloc(bloblen)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    p = blob;
    PUT_32BIT_MSB_FIRST(p, 7);
    p += 4;
    memcpy(p, "ssh-dss", 7);
    p += 7;
    PUT_32BIT_MSB_FIRST(p, plen);
    p += 4;
    for (i = plen; i--;)
	*p++ = bignum_byte(dss->p, i);
    PUT_32BIT_MSB_FIRST(p, qlen);
    p += 4;
    for (i = qlen; i--;)
	*p++ = bignum_byte(dss->q, i);
    PUT_32BIT_MSB_FIRST(p, glen);
    p += 4;
    for (i = glen; i--;)
	*p++ = bignum_byte(dss->g, i);
    PUT_32BIT_MSB_FIRST(p, ylen);
    p += 4;
    for (i = ylen; i--;)
	*p++ = bignum_byte(dss->y, i);
    assert(p == blob + bloblen);
    *len = bloblen;
    return blob;
}

static void *dss_createkey(unsigned char *pub_blob, int pub_len,
			   unsigned char *priv_blob, int priv_len)
{
    struct dss_key *dss;
    char *pb = (char *) priv_blob;
    char *hash;
    int hashlen;
    SHA_State s;
    unsigned char digest[20];
    Bignum ytest;

    dss = dss_newkey((char *) pub_blob, pub_len);
    dss->x = getmp(&pb, &priv_len);

    /*
     * Check the obsolete hash in the old DSS key format.
     */
    hashlen = -1;
    getstring(&pb, &priv_len, &hash, &hashlen);
    if (hashlen == 20) {
	SHA_Init(&s);
	sha_mpint2(&s, dss->p);
	sha_mpint2(&s, dss->q);
	sha_mpint2(&s, dss->g);
	SHA_Final(&s, digest);
	if (0 != memcmp(hash, digest, 20)) {
	    dss_freekey(dss);
	    return NULL;
	}
    }

    /*
     * Now ensure g^x mod p really is y.
     */
    ytest = modpow(dss->g, dss->x, dss->p);
    if (0 != bignum_cmp(ytest, dss->y)) {
	dss_freekey(dss);
	return NULL;
    }
    freebn(ytest);

    return dss;
}

unsigned char *dss_sign(void *key, char *data, int datalen, int *siglen)
{
    /*
     * The basic DSS signing algorithm is:
     * 
     *  - invent a random k between 1 and q-1 (exclusive).
     *  - Compute r = (g^k mod p) mod q.
     *  - Compute s = k^-1 * (hash + x*r) mod q.
     * 
     * This has the dangerous properties that:
     * 
     *  - if an attacker in possession of the public key _and_ the
     *    signature (for example, the host you just authenticated
     *    to) can guess your k, he can reverse the computation of s
     *    and work out x = r^-1 * (s*k - hash) mod q. That is, he
     *    can deduce the private half of your key, and masquerade
     *    as you for as long as the key is still valid.
     * 
     *  - since r is a function purely of k and the public key, if
     *    the attacker only has a _range of possibilities_ for k
     *    it's easy for him to work through them all and check each
     *    one against r; he'll never be unsure of whether he's got
     *    the right one.
     * 
     *  - if you ever sign two different hashes with the same k, it
     *    will be immediately obvious because the two signatures
     *    will have the same r, and moreover an attacker in
     *    possession of both signatures (and the public key of
     *    course) can compute k = (hash1-hash2) * (s1-s2)^-1 mod q,
     *    and from there deduce x as before.
     * 
     *  - the Bleichenbacher attack on DSA makes use of methods of
     *    generating k which are significantly non-uniformly
     *    distributed; in particular, generating a 160-bit random
     *    number and reducing it mod q is right out.
     * 
     * For this reason we must be pretty careful about how we
     * generate our k. Since this code runs on Windows, with no
     * particularly good system entropy sources, we can't trust our
     * RNG itself to produce properly unpredictable data. Hence, we
     * use a totally different scheme instead.
     * 
     * What we do is to take a SHA-512 (_big_) hash of the private
     * key x, and then feed this into another SHA-512 hash that
     * also includes the message hash being signed. That is:
     * 
     *   proto_k = SHA512 ( SHA512(x) || SHA160(message) )
     * 
     * This number is 512 bits long, so reducing it mod q won't be
     * noticeably non-uniform. So
     * 
     *   k = proto_k mod q
     * 
     * This has the interesting property that it's _deterministic_:
     * signing the same hash twice with the same key yields the
     * same signature.
     * 
     * Despite this determinism, it's still not predictable to an
     * attacker, because in order to repeat the SHA-512
     * construction that created it, the attacker would have to
     * know the private key value x - and by assumption he doesn't,
     * because if he knew that he wouldn't be attacking k!
     *
     * (This trick doesn't, _per se_, protect against reuse of k.
     * Reuse of k is left to chance; all it does is prevent
     * _excessively high_ chances of reuse of k due to entropy
     * problems.)
     * 
     * Thanks to Colin Plumb for the general idea of using x to
     * ensure k is hard to guess, and to the Cambridge University
     * Computer Security Group for helping to argue out all the
     * fine details.
     */
    struct dss_key *dss = (struct dss_key *) key;
    SHA512_State ss;
    unsigned char digest[20], digest512[64];
    Bignum proto_k, k, gkp, hash, kinv, hxr, r, s;
    unsigned char *bytes;
    int nbytes, i;

    SHA_Simple(data, datalen, digest);

    /*
     * Hash some identifying text plus x.
     */
    SHA512_Init(&ss);
    SHA512_Bytes(&ss, "DSA deterministic k generator", 30);
    sha512_mpint(&ss, dss->x);
    SHA512_Final(&ss, digest512);

    /*
     * Now hash that digest plus the message hash.
     */
    SHA512_Init(&ss);
    SHA512_Bytes(&ss, digest512, sizeof(digest512));
    SHA512_Bytes(&ss, digest, sizeof(digest));
    SHA512_Final(&ss, digest512);

    memset(&ss, 0, sizeof(ss));

    /*
     * Now convert the result into a bignum, and reduce it mod q.
     */
    proto_k = bignum_from_bytes(digest512, 64);
    k = bigmod(proto_k, dss->q);
    freebn(proto_k);

    memset(digest512, 0, sizeof(digest512));

    /*
     * Now we have k, so just go ahead and compute the signature.
     */
    gkp = modpow(dss->g, k, dss->p);   /* g^k mod p */
    r = bigmod(gkp, dss->q);	       /* r = (g^k mod p) mod q */
    freebn(gkp);

    hash = bignum_from_bytes(digest, 20);
    kinv = modinv(k, dss->q);	       /* k^-1 mod q */
    free(k);
    hxr = bigmuladd(dss->x, r, hash);  /* hash + x*r */
    s = modmul(kinv, hxr, dss->q);     /* s = k^-1 * (hash + x*r) mod q */
    freebn(hxr);
    freebn(kinv);
    freebn(hash);

    /*
     * Signature blob is
     * 
     *   string  "ssh-dss"
     *   string  two 20-byte numbers r and s, end to end
     * 
     * i.e. 4+7 + 4+40 bytes.
     */
    nbytes = 4 + 7 + 4 + 40;
    if((bytes = malloc(nbytes)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    PUT_32BIT_MSB_FIRST(bytes, 7);
    memcpy(bytes + 4, "ssh-dss", 7);
    PUT_32BIT_MSB_FIRST(bytes + 4 + 7, 40);
    for (i = 0; i < 20; i++) {
	bytes[4 + 7 + 4 + i] = bignum_byte(r, 19 - i);
	bytes[4 + 7 + 4 + 20 + i] = bignum_byte(s, 19 - i);
    }
    freebn(r);
    freebn(s);

    *siglen = nbytes;
    return bytes;
}

const struct ssh_signkey ssh_dss = {
    dss_public_blob,
    dss_createkey,
    dss_sign,
    "ssh-dss",
};
