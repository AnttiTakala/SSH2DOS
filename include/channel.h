#ifndef _CHANNEL_H
#define _CHANNEL_H

extern void SSH2_Channel_PktInit(unsigned char);
extern short SSH2_Channel_Read(unsigned char);
extern void SSH2_Channel_Send(unsigned char *, unsigned short);
extern short SSH2_Channel_Open(void);

#endif
