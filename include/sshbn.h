#ifndef _BN_H
#define _BN_H

/* Bignum functions */

typedef unsigned short *Bignum;

extern unsigned short ssh1_read_bignum(unsigned char *, Bignum *);
extern unsigned short ssh1_bignum_length(Bignum);
extern unsigned short ssh1_write_bignum(void *, Bignum);
extern Bignum modpow(Bignum, Bignum, Bignum);
extern Bignum modmul(Bignum, Bignum, Bignum);
extern Bignum bigmul(Bignum, Bignum);
extern Bignum bignum_from_bytes(unsigned char *, unsigned short);
extern Bignum copybn(Bignum);
extern unsigned short bignum_bitcount(Bignum);
extern unsigned char bignum_byte(Bignum, unsigned short);
extern short bignum_cmp(Bignum, Bignum);
extern void decbn(Bignum);
extern void freebn(Bignum);

extern Bignum bignum_bitmask(Bignum);
extern Bignum bignum_rshift(Bignum, unsigned short);
extern Bignum modinv(Bignum, Bignum);
extern Bignum bn_power_2(unsigned short);
extern Bignum bigmod(Bignum, Bignum);
extern Bignum bigmuladd(Bignum, Bignum, Bignum);
extern void bignum_set_bit(Bignum, unsigned short, unsigned short);

#endif
