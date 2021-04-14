#ifndef _AUTH_H
#define _AUTH_H

extern void SSH2_Auth_PktInit(char, char *);
extern short SSH2_Auth_Read(unsigned char);
extern short SSH2_Auth_Pubkey(char *, char *);
extern short SSH2_Auth_Password(char *, char *);
extern short SSH2_Auth_KbdInt(char *, char *);

#endif
