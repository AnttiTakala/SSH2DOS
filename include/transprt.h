#ifndef _TRANSPRT_H
#define _TRANSPRT_H

/* Packet structure */

typedef struct {
    unsigned long length;	/* body length */
    unsigned long maxlen;	/* max length */
    unsigned char type;		/* packet type */
    unsigned char *whole;	/* pointer to whole packet */
    unsigned char *body;	/* pointer to useful data */
    unsigned char *ptr;		/* sliding pointer in body */
} Packet;

/* Initialize important variables */
void SSH2_init(void);

/* request compression from server */
void Request_Compression(int);

/* free compression memory */
void Disable_Compression(void);

/* get a packet from the transport layer */
short SSH_pkt_read(unsigned char);

/* create header for raw outgoing packet */
void SSH_pkt_init(unsigned char);

/* create outgoing packet */
void SSH_pkt_send(void);

/* SSH2 packet assembly */
void SSH_putuint32(unsigned long);
void SSH_putbool(unsigned char);
void SSH_putstring(unsigned char *);
void SSH_putdata(unsigned char *, unsigned short);
unsigned short SSH_putmp(unsigned short *);

/* SSH2 packet disassembly */
unsigned long SSH_getuint32(void);
unsigned int SSH_getbool(void);
void SSH_getstring(char **, unsigned long *);

/* SSH2 disconnect */
void SSH_Disconnect(unsigned long, const char *, ...);

#endif
