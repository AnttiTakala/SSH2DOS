/*
 * Bignum routines
 *
 * Taken from the PuTTY source.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sshbn.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

unsigned short bnZero[1] = { 0 };
unsigned short bnOne[2] = { 1, 1 };

/*
 * The Bignum format is an array of `unsigned short'. The first
 * element of the array counts the remaining elements. The
 * remaining elements express the actual number, base 2^16, _least_
 * significant digit first. (So it's trivial to extract the bit
 * with value 2^n for any n.)
 *
 * All Bignums in this module are positive. Negative numbers must
 * be dealt with outside it.
 *
 * INVARIANT: the most significant word of any Bignum must be
 * nonzero.
 */

Bignum Zero = bnZero, One = bnOne;

static Bignum newbn(unsigned short length)
{
Bignum b;

    if((b = (Bignum)malloc((length + 1) * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    memset(b, 0, (length + 1) * sizeof(*b));
    b[0] = length;
    return b;
}

Bignum copybn(Bignum orig)
{
Bignum b;

    if((b = (Bignum)malloc((orig[0] + 1) * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    memcpy(b, orig, (orig[0] + 1) * sizeof(*b));
    return b;
}

void freebn(Bignum b)
{
    /*
     * Burn the evidence, just in case.
     */
    memset(b, 0, sizeof(b[0]) * (b[0] + 1));
    free(b);
}

/*
 * Compute c = a * b.
 * Input is in the first len words of a and b.
 * Result is returned in the first 2*len words of c.
 */
static void internal_mul(unsigned short *a, unsigned short *b,
			 unsigned short *c, unsigned short len)
{
short i, j;
unsigned long ai, t;

    for (j = 0; j < 2 * len; j++)
	c[j] = 0;

    for (i = len - 1; i >= 0; i--) {
	ai = (unsigned long)a[i];
	t = 0;
	for (j = len - 1; j >= 0; j--) {
	    t += ai * (unsigned long) b[j];
	    t += (unsigned long) c[i + j + 1];
	    c[i + j + 1] = (unsigned short) t;
	    t = t >> 16;
	}
	c[i] = (unsigned short) t;
    }
}

static void internal_add_shifted(unsigned short *number,
				 unsigned short n, unsigned short shift)
{
unsigned short word, bshift;
unsigned long addend;

    word = 1 + (shift / 16);
    bshift = shift % 16;
    addend = (unsigned long)n << bshift;

    while (addend) {
	addend += number[word];
	number[word] = (unsigned short) addend & 0xFFFF;
	addend >>= 16;
	word++;
    }
}

/*
 * Compute a = a % m.
 * Input in first alen words of a and first mlen words of m.
 * Output in first alen words of a
 * (of which first alen-mlen words will be zero).
 * The MSW of m MUST have its high bit set.
 * Quotient is accumulated in the `quotient' array, which is a Bignum
 * rather than the internal bigendian format. Quotient parts are shifted
 * left by `qshift' before adding into quot.
 */
static void internal_mod(unsigned short *a, unsigned short alen,
			 unsigned short *m, unsigned short mlen,
			 unsigned short *quot, unsigned short qshift)
{
unsigned short i, m0, m1;
unsigned short h, ai1;
short k;
unsigned long t, q, r, c;

    m0 = m[0];
    if (mlen > 1)
	m1 = m[1];
    else
	m1 = 0;

    for (i = 0; i <= alen - mlen; i++) {
	if (i == 0)
	    h = 0;
	else {
	    h = a[i - 1];
	    a[i - 1] = 0;
	}

	if (i == alen - 1)
	    ai1 = 0;
	else
	    ai1 = a[i + 1];

	/* Find q = h:a[i] / m0 */
	t = ((unsigned long) h << 16) + (unsigned long)a[i];
	q = t / m0;
	r = t % m0;

	/* Refine our estimate of q by looking at
	   h:a[i]:a[i+1] / m0:m1 */
	t = (unsigned long)m1 * (unsigned long)q;
	if (t > (r << 16) + ai1) {
	    q--;
	    t -= m1;
	    r = (r + m0) & 0xffff;     /* overflow? */
	    if (r >= (unsigned long) m0 &&
		t > ( r << 16) + ai1) q--;
	}

	/* Subtract q * m from a[i...] */
	c = 0;
	for (k = mlen - 1; k >= 0; k--) {
	    t = (long) q *(long) m[k];
	    t += c;
	    c = t >> 16;
	    if ((unsigned short) t > a[i + k])
		c++;
	    a[i + k] -= (unsigned short) t;
	}

	/* Add back m in case of borrow */
	if (c != h) {
	    t = 0;
	    for (k = mlen - 1; k >= 0; k--) {
		t += m[k];
		t += a[i + k];
		a[i + k] = (unsigned short) t;
		t = t >> 16;
	    }
	    q--;
	}
	if (quot)
	    internal_add_shifted(quot, q, qshift + 16 * (alen - mlen - i));
    }
}

/*
 * Compute (base ^ exp) % mod.
 * The base MUST be smaller than the modulus.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 */
Bignum modpow(Bignum base, Bignum exp, Bignum mod)
{
unsigned short *a, *b, *n, *m, *t;
unsigned short mshift, mlen, i;
short j;
Bignum result;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    if((m = malloc(mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < 15; mshift++)
	if ((m[0] << mshift) & 0x8000)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (16 - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    /* Allocate n of size mlen, copy base to n */
    if((n = malloc(mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    i = mlen - base[0];
    for (j = 0; j < i; j++)
	n[j] = 0;
    for (j = 0; j < base[0]; j++)
	n[i + j] = base[base[0] - j];

    /* Allocate a and b of size 2*mlen. Set a = 1 */
    if((a = malloc(2 * mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    if((b = malloc(2 * mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (i = 0; i < 2 * mlen; i++)
	a[i] = 0;
    a[2 * mlen - 1] = 1;

    /* Skip leading zero bits of exp. */
    i = 0;
    j = 15;
    while (i < exp[0] && (exp[exp[0] - i] & (1 << j)) == 0) {
	j--;
	if (j < 0) {
	    i++;
	    j = 15;
	}
    }

    /* Main computation */
    while (i < exp[0]) {
	while (j >= 0) {
	    internal_mul(a + mlen, a + mlen, b, mlen);
	    internal_mod(b, mlen * 2, m, mlen, NULL, 0);
	    if ((exp[exp[0] - i] & (1 << j)) != 0) {
		internal_mul(b + mlen, n, a, mlen);
		internal_mod(a, mlen * 2, m, mlen, NULL, 0);
	    } else {
		t = a;
		a = b;
		b = t;
	    }
	    j--;
	}
	i++;
	j = 15;
    }

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = mlen - 1; i < 2 * mlen - 1; i++)
	    a[i] = (a[i] << mshift) | (a[i + 1] >> (16 - mshift));
	a[2 * mlen - 1] = a[2 * mlen - 1] << mshift;
	internal_mod(a, mlen * 2, m, mlen, NULL, 0);
	for (i = 2 * mlen - 1; i >= mlen; i--)
	    a[i] = (a[i] >> mshift) | (a[i - 1] << (16 - mshift));
    }

    /* Copy result to buffer */
    result = newbn(mod[0]);
    for (i = 0; i < mlen; i++)
	result[result[0] - i] = a[i + mlen];
    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;

    /* Free temporary arrays */
    for (i = 0; i < 2 * mlen; i++)
	a[i] = 0;
    free(a);
    for (i = 0; i < 2 * mlen; i++)
	b[i] = 0;
    free(b);
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    free(m);
    for (i = 0; i < mlen; i++)
	n[i] = 0;
    free(n);

    return result;
}

/*
 * Compute (p * q) % mod.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 */
Bignum modmul(Bignum p, Bignum q, Bignum mod)
{
unsigned short *a, *n, *m, *o;
unsigned short mlen, pqlen, rlen, mshift;
short i, j;
Bignum result;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    if((m = malloc(mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < 15; mshift++)
	if ((m[0] << mshift) & 0x8000)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (16 - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    pqlen = (p[0] > q[0] ? p[0] : q[0]);

    /* Allocate n of size pqlen, copy p to n */
    if((n = malloc(pqlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    i = pqlen - p[0];
    for (j = 0; j < i; j++)
	n[j] = 0;
    for (j = 0; j < p[0]; j++)
	n[i + j] = p[p[0] - j];

    /* Allocate o of size pqlen, copy q to o */
    if((o = malloc(pqlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    i = pqlen - q[0];
    for (j = 0; j < i; j++)
	o[j] = 0;
    for (j = 0; j < q[0]; j++)
	o[i + j] = q[q[0] - j];

    /* Allocate a of size 2*pqlen for result */
    if((a = malloc(2 * pqlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

    /* Main computation */
    internal_mul(n, o, a, pqlen);
    internal_mod(a, pqlen * 2, m, mlen, NULL, 0);

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = 2 * pqlen - mlen - 1; i < 2 * pqlen - 1; i++)
	    a[i] = (a[i] << mshift) | (a[i + 1] >> (16 - mshift));
	a[2 * pqlen - 1] = a[2 * pqlen - 1] << mshift;
	internal_mod(a, pqlen * 2, m, mlen, NULL, 0);
	for (i = 2 * pqlen - 1; i >= 2 * pqlen - mlen; i--)
	    a[i] = (a[i] >> mshift) | (a[i - 1] << (16 - mshift));
    }

    /* Copy result to buffer */
    rlen = (mlen < pqlen * 2 ? mlen : pqlen * 2);
    result = newbn(rlen);
    for (i = 0; i < rlen; i++)
	result[result[0] - i] = a[i + 2 * pqlen - rlen];
    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;

    /* Free temporary arrays */
    for (i = 0; i < 2 * pqlen; i++)
	a[i] = 0;
    free(a);
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    free(m);
    for (i = 0; i < pqlen; i++)
	n[i] = 0;
    free(n);
    for (i = 0; i < pqlen; i++)
	o[i] = 0;
    free(o);

    return result;
}

/*
 * Decrement a number.
 */
void decbn(Bignum bn)
{
unsigned short i = 1;

    while (i < bn[0] && bn[i] == 0)
	bn[i++] = 0xFFFF;
    bn[i]--;
}

Bignum bignum_from_bytes(unsigned char *data, unsigned short nbytes)
{
Bignum result;
unsigned short w, i;
unsigned char byte;    

    w = (nbytes + 1) / 2;	       /* bytes -> words */

    result = newbn(w);
    for (i = 1; i <= w; i++)
	result[i] = 0;
    for (i = nbytes; i--;) {
	byte = *data++;
	if (i & 1)
	    result[1 + i / 2] |= byte << 8;
	else
	    result[1 + i / 2] |= byte;
    }

    while (result[0] > 1 && result[result[0]] == 0)
	result[0]--;
    return result;
}

/*
 * Read an ssh1-format bignum from a data buffer. Return the number
 * of bytes consumed.
 */
unsigned short ssh1_read_bignum(unsigned char *data, Bignum * result)
{
unsigned char *p = data;
unsigned short i, w, b;

    w = 0;
    for (i = 0; i < 2; i++)
	w = (w << 8) + *p++;
    b = (w + 7) / 8;		       /* bits -> bytes */

    if (!result)		       /* just return length */
	return b + 2;

    *result = bignum_from_bytes(p, b);

    return p + b - data;
}

/*
 * Return the bit count of a bignum, for ssh1 encoding.
 */
unsigned short bignum_bitcount(Bignum bn)
{
    short bitcount = bn[0] * 16 - 1;
    while (bitcount >= 0
	   && (bn[bitcount / 16 + 1] >> (bitcount % 16)) == 0) bitcount--;
    return bitcount + 1;
}

/*
 * Return the byte length of a bignum when ssh1 encoded.
 */
unsigned short ssh1_bignum_length(Bignum bn)
{
    return 2 + (bignum_bitcount(bn) + 7) / 8;
}

/*
 * Return a byte from a bignum; 0 is least significant, etc.
 */
unsigned char bignum_byte(Bignum bn, unsigned short i)
{
    if (i >= 2 * bn[0])
	return 0;		       /* beyond the end */
    else if (i & 1)
	return (bn[i / 2 + 1] >> 8) & 0xFF;
    else
	return (bn[i / 2 + 1]) & 0xFF;
}

/*
 * Write a ssh1-format bignum into a buffer. It is assumed the
 * buffer is big enough. Returns the number of bytes used.
 */
unsigned short ssh1_write_bignum(void *data, Bignum bn)
{
unsigned char *p = data;
unsigned short len = ssh1_bignum_length(bn);
short i;
unsigned short bitc = bignum_bitcount(bn);

    *p++ = (bitc >> 8) & 0xFF;
    *p++ = (bitc) & 0xFF;
    for (i = len - 2; i--;)
	*p++ = bignum_byte(bn, i);
    return len;
}

/*
 * Compare two bignums. Returns like strcmp.
 */
short bignum_cmp(Bignum a, Bignum b)
{
    unsigned short amax = a[0], bmax = b[0];
    short i = (amax > bmax ? amax : bmax);
    while (i) {
	unsigned short aval = (i > amax ? 0 : a[i]);
	unsigned short bval = (i > bmax ? 0 : b[i]);
	if (aval < bval)
	    return -1;
	if (aval > bval)
	    return +1;
	i--;
    }
    return 0;
}

/*
 * Non-modular multiplication and addition.
 */
Bignum bigmuladd(Bignum a, Bignum b, Bignum addend)
{
    unsigned short alen, blen, mlen;
    unsigned short rlen, i, maxspot;
    unsigned short *workspace;
    Bignum ret;

    alen = a[0]; blen = b[0];
    mlen = (alen > blen ? alen : blen);

    /* mlen space for a, mlen space for b, 2*mlen for result */
    if((workspace = malloc(mlen * 4 * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (i = 0; i < mlen; i++) {
	workspace[0 * mlen + i] = (mlen - i <= a[0] ? a[mlen - i] : 0);
	workspace[1 * mlen + i] = (mlen - i <= b[0] ? b[mlen - i] : 0);
    }

    internal_mul(workspace + 0 * mlen, workspace + 1 * mlen,
		 workspace + 2 * mlen, mlen);

    /* now just copy the result back */
    rlen = alen + blen + 1;
    if (addend && rlen <= addend[0])
	rlen = addend[0] + 1;
    ret = newbn(rlen);
    maxspot = 0;
    for (i = 1; i <= ret[0]; i++) {
	ret[i] = (i <= 2 * mlen ? workspace[4 * mlen - i] : 0);
	if (ret[i] != 0)
	    maxspot = i;
    }
    ret[0] = maxspot;

    /* now add in the addend, if any */
    if (addend) {
	unsigned long carry = 0;
	for (i = 1; i <= rlen; i++) {
	    carry += (i <= ret[0] ? ret[i] : 0);
	    carry += (i <= addend[0] ? addend[i] : 0);
	    ret[i] = (unsigned short) carry & 0xFFFF;
	    carry >>= 16;
	    if (ret[i] != 0 && i > maxspot)
		maxspot = i;
	}
    }
    ret[0] = maxspot;

    return ret;
}

/*
 * Non-modular multiplication.
 */
Bignum bigmul(Bignum a, Bignum b)
{
    return bigmuladd(a, b, NULL);
}

/*
 * Right-shift one bignum to form another.
 */
Bignum bignum_rshift(Bignum a, unsigned short shift)
{
Bignum ret;
unsigned short i, shiftw, shiftb, shiftbb, bits;
unsigned short ai, ai1;

    bits = bignum_bitcount(a) - shift;
    ret = newbn((bits + 15) / 16);

    if (ret) {
	shiftw = shift / 16;
	shiftb = shift % 16;
	shiftbb = 16 - shiftb;

	ai1 = a[shiftw + 1];
	for (i = 1; i <= ret[0]; i++) {
	    ai = ai1;
	    ai1 = (i + shiftw + 1 <= a[0] ? a[i + shiftw + 1] : 0);
	    ret[i] = ((ai >> shiftb) | (ai1 << shiftbb)) & 0xFFFF;
	}
    }

    return ret;
}

/*
 * Create a bignum which is the bitmask covering another one. That
 * is, the smallest integer which is >= N and is also one less than
 * a power of two.
 */
Bignum bignum_bitmask(Bignum n)
{
Bignum ret = copybn(n);
short i;
unsigned short j;

    i = ret[0];
    while (n[i] == 0 && i > 0)
	i--;
    if (i <= 0)
	return ret;		       /* input was zero */
    j = 1;
    while (j < n[i])
	j = 2 * j + 1;
    ret[i] = j;
    while (--i > 0)
	ret[i] = 0xFFFF;
    return ret;
}

/*
 * Set a bit in a bignum; 0 is least significant, etc.
 */
void bignum_set_bit(Bignum bn, unsigned short bitnum, unsigned short value)
{
    if (bitnum >= 16 * bn[0])
	abort();		       /* beyond the end */
    else {
	unsigned short v = bitnum / 16 + 1;
	unsigned short mask = 1 << (bitnum % 16);
	if (value)
	    bn[v] |= mask;
	else
	    bn[v] &= ~mask;
    }
}


Bignum bn_power_2(unsigned short n)
{
    Bignum ret = newbn(n / 16 + 1);
    bignum_set_bit(ret, n, 1);
    return ret;
}

/*
 * Compute p % mod.
 * The most significant word of mod MUST be non-zero.
 * We assume that the result array is the same size as the mod array.
 * We optionally write out a quotient if `quotient' is non-NULL.
 * We can avoid writing out the result if `result' is NULL.
 */
void bigdivmod(Bignum p, Bignum mod, Bignum result, Bignum quotient)
{
    unsigned short *n, *m;
    short mshift;
    short plen, mlen, i, j;

    /* Allocate m of size mlen, copy mod to m */
    /* We use big endian internally */
    mlen = mod[0];
    if((m = malloc(mlen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (j = 0; j < mlen; j++)
	m[j] = mod[mod[0] - j];

    /* Shift m left to make msb bit set */
    for (mshift = 0; mshift < 15; mshift++)
	if ((m[0] << mshift) & 0x8000)
	    break;
    if (mshift) {
	for (i = 0; i < mlen - 1; i++)
	    m[i] = (m[i] << mshift) | (m[i + 1] >> (16 - mshift));
	m[mlen - 1] = m[mlen - 1] << mshift;
    }

    plen = p[0];
    /* Ensure plen > mlen */
    if (plen <= mlen)
	plen = mlen + 1;

    /* Allocate n of size plen, copy p to n */
    if((n = malloc(plen * sizeof(unsigned short))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    for (j = 0; j < plen; j++)
	n[j] = 0;
    for (j = 1; j <= p[0]; j++)
	n[plen - j] = p[j];

    /* Main computation */
    internal_mod(n, plen, m, mlen, quotient, mshift);

    /* Fixup result in case the modulus was shifted */
    if (mshift) {
	for (i = plen - mlen - 1; i < plen - 1; i++)
	    n[i] = (n[i] << mshift) | (n[i + 1] >> (16 - mshift));
	n[plen - 1] = n[plen - 1] << mshift;
	internal_mod(n, plen, m, mlen, quotient, 0);
	for (i = plen - 1; i >= plen - mlen; i--)
	    n[i] = (n[i] >> mshift) | (n[i - 1] << (16 - mshift));
    }

    /* Copy result to buffer */
    if (result) {
	for (i = 1; i <= result[0]; i++) {
	    j = plen - i;
	    result[i] = j >= 0 ? n[j] : 0;
	}
    }

    /* Free temporary arrays */
    for (i = 0; i < mlen; i++)
	m[i] = 0;
    free(m);
    for (i = 0; i < plen; i++)
	n[i] = 0;
    free(n);
}


/*
 * Simple remainder.
 */
Bignum bigmod(Bignum a, Bignum b)
{
    Bignum r = newbn(b[0]);
    bigdivmod(a, b, r, NULL);
    return r;
}

/*
 * Modular inverse, using Euclid's extended algorithm.
 */
Bignum modinv(Bignum number, Bignum modulus)
{
    Bignum a = copybn(modulus);
    Bignum b = copybn(number);
    Bignum xp = copybn(Zero);
    Bignum x = copybn(One);
    short sign = +1;

    while (bignum_cmp(b, One) != 0) {
	Bignum t = newbn(b[0]);
	Bignum q = newbn(a[0]);
	bigdivmod(a, b, t, q);
	while (t[0] > 1 && t[t[0]] == 0)
	    t[0]--;
	freebn(a);
	a = b;
	b = t;
	t = xp;
	xp = x;
	x = bigmuladd(q, xp, t);
	sign = -sign;
	freebn(t);
    }

    freebn(b);
    freebn(a);
    freebn(xp);

    /* now we know that sign * x == 1, and that x < modulus */
    if (sign < 0) {
	/* set a new x to be modulus - x */
	Bignum newx = newbn(modulus[0]);
	unsigned short carry = 0;
	short maxspot = 1;
	short i;

	for (i = 1; i <= newx[0]; i++) {
	    unsigned short aword = (i <= modulus[0] ? modulus[i] : 0);
	    unsigned short bword = (i <= x[0] ? x[i] : 0);
	    newx[i] = aword - bword - carry;
	    bword = ~bword;
	    carry = carry ? (newx[i] >= bword) : (newx[i] > bword);
	    if (newx[i] != 0)
		maxspot = i;
	}
	newx[0] = maxspot;
	freebn(x);
	x = newx;
    }

    /* and return. */
    return x;
}
