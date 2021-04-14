/*
 * Header for int64.c.
 */

#ifndef PUTTY_INT64_H
#define PUTTY_INT64_H

typedef struct {
    unsigned long hi, lo;
} uint64, int64;

extern uint64 uint64_div10(uint64 x, int *remainder);
extern void uint64_decimal(uint64 x, char *buffer);
extern uint64 uint64_make(unsigned long hi, unsigned long lo);
extern uint64 uint64_add(uint64 x, uint64 y);
extern uint64 uint64_add32(uint64 x, unsigned long y);
extern int uint64_compare(uint64 x, uint64 y);

#endif
