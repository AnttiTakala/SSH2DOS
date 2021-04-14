#ifndef _MACROS_H
#define _MACROS_H

/* Common macros  */

#define GET_32BIT_LSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[0]) | \
  ((unsigned long)(unsigned char)(cp)[1] << 8) | \
  ((unsigned long)(unsigned char)(cp)[2] << 16) | \
  ((unsigned long)(unsigned char)(cp)[3] << 24))

#define PUT_32BIT_LSB_FIRST(cp, value) ( \
  (cp)[0] = (value), \
  (cp)[1] = (unsigned long)(value) >> 8, \
  (cp)[2] = (unsigned long)(value) >> 16, \
  (cp)[3] = (unsigned long)(value) >> 24 )

#define GET_32BIT_MSB_FIRST(cp) \
  (((unsigned long)(unsigned char)(cp)[3]) | \
  ((unsigned long)(unsigned char)(cp)[2] << 8) | \
  ((unsigned long)(unsigned char)(cp)[1] << 16) | \
  ((unsigned long)(unsigned char)(cp)[0] << 24))

#define PUT_32BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (unsigned long)(value) >> 24, \
  (cp)[1] = (unsigned long)(value) >> 16, \
  (cp)[2] = (unsigned long)(value) >> 8, \
  (cp)[3] = (value) )

#define PUT_16BIT_MSB_FIRST(cp, value) ( \
  (cp)[0] = (value) >> 8, \
  (cp)[1] = (value) )

#endif
