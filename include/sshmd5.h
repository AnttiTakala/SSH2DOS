#ifndef _MD5_H
#define _MD5_H

#include "type.h"

/* MD5 hash functions */

extern void MD5Init(void);
extern void MD5Update(const char *buf, unsigned len);
extern void MD5Final(char digest[16]);

#endif
