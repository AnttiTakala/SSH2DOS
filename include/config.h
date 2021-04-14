#ifndef _CONFIG_H
#define _CONFIG_H

#include "tcp.h"

typedef void (*SendFuncPtr)(char *, unsigned short);

#define MAX_PASSWORD_LENGTH 30

/* Configuration options */
typedef struct {
	char *identity;
	tcp_Socket s;
	FILE *debugfile;
	FILE *brailab;
	FILE *batchfile;
} Config;

/* Configuration options stored in bits */
#define CIPHER_ENABLED		1
#define PRESERVE_ATTRIBUTES	2
#define RECURSIVE_COPY		4
#define VERBOSE_MODE		8
#define QUIET_MODE		16
#define COMPRESSION_REQUESTED	32
#define COMPRESSION_ENABLED	64
#define NONPRIVILEGED_PORT	128
#define NEWLINE			256
#define CONVERT_LOWERCASE	512
#define BIOS			1024
#define SFTP_CONNECTED		2048
#define DHGROUP			4096
#define NOVESA			8192

#endif
