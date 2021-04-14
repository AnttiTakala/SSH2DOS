#ifndef _SHA_H
#define _SHA_H

#include "type.h"
#include "sshbn.h"
#include "int64.h"

typedef struct {
    uint32 h[5];
    unsigned char block[64];
    int blkused;
    uint32 lenhi, lenlo;
} SHA_State;

typedef struct {
    uint64 h[8];
    unsigned char block[128];
    int blkused;
    uint32 len[4];
} SHA512_State;

void SHA512_Init(SHA512_State * s);
void SHA512_Bytes(SHA512_State * s, const void *p, int len);
void SHA512_Final(SHA512_State * s, unsigned char *output);

void sha1_cskey(unsigned char *);
void sha1_sckey(unsigned char *);

void SHA_Init(SHA_State *);
void SHA_Bytes(SHA_State *, void *, short);
void SHA_Final(SHA_State *, unsigned char *);
void SHA_Simple(void *, int, unsigned char *);
void hmac_sha1_simple(void *, int, void *, int, unsigned char *);

void sha1_generate(unsigned char *, unsigned short, unsigned long);
int sha1_verify(unsigned char *, unsigned short, unsigned long);

void sha_string(SHA_State *, void *, unsigned long);
unsigned char *ssh2_mpint_fmt(Bignum, unsigned long *);
void sha_mpint(SHA_State *, Bignum);

#endif
