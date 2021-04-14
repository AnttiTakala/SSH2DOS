#ifndef _SSH_H
#define _SSH_H

/* SSH constants and protocol structure */

#define MAX_PACKET_SIZE 8192	/* max packet size */
#define EXIT_SSH 1381

#define SSH_PORT 22

#define SSH_MSG_DISCONNECT		  1
#define SSH_MSG_IGNORE			  2
#define SSH_MSG_UNIMPLEMENTED		  3
#define SSH_MSG_DEBUG			  4
#define SSH_MSG_SERVICE_REQUEST		  5
#define SSH_MSG_SERVICE_ACCEPT		  6
#define SSH_MSG_KEXINIT			  20
#define SSH_MSG_NEWKEYS			  21
#define SSH_MSG_KEXDH_INIT		  30
#define SSH_MSG_KEXDH_REPLY		  31
#define SSH_MSG_KEX_DH_GEX_REQUEST        30
#define SSH_MSG_KEX_DH_GEX_GROUP          31
#define SSH_MSG_KEX_DH_GEX_INIT           32
#define SSH_MSG_KEX_DH_GEX_REPLY          33


#define SSH_MSG_USERAUTH_REQUEST          50
#define SSH_MSG_USERAUTH_FAILURE          51
#define SSH_MSG_USERAUTH_SUCCESS          52
#define SSH_MSG_USERAUTH_BANNER           53
#define SSH_MSG_USERAUTH_PK_OK            60
#define SSH_MSG_USERAUTH_PASSWD_CHANGEREQ 60
#define SSH_MSG_USERAUTH_INFO_REQUEST     60
#define SSH_MSG_USERAUTH_INFO_RESPONSE    61
#define SSH_MSG_GLOBAL_REQUEST            80
#define SSH_MSG_REQUEST_SUCCESS           81
#define SSH_MSG_REQUEST_FAILURE           82
#define SSH_MSG_CHANNEL_OPEN              90
#define SSH_MSG_CHANNEL_OPEN_CONFIRMATION 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE      92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST     93
#define SSH_MSG_CHANNEL_DATA              94
#define SSH_MSG_CHANNEL_EXTENDED_DATA     95
#define SSH_MSG_CHANNEL_EOF               96
#define SSH_MSG_CHANNEL_CLOSE             97
#define SSH_MSG_CHANNEL_REQUEST           98
#define SSH_MSG_CHANNEL_SUCCESS           99
#define SSH_MSG_CHANNEL_FAILURE           100

/* Major protocol version.  Different version indicates major incompatiblity
   that prevents communication.  */
#define PROTOCOL_MAJOR          2

/* Minor protocol version.  Different version indicates minor incompatibility
   that does not prevent interoperation. */
#define PROTOCOL_MINOR          0

enum {
    SSH_KEYTYPE_UNOPENABLE,
    SSH_KEYTYPE_UNKNOWN,
    SSH_KEYTYPE_SSH1, SSH_KEYTYPE_SSH2,
    SSH_KEYTYPE_OPENSSH, SSH_KEYTYPE_SSHCOM
};

#define SSH_DISCONNECT_PROTOCOL_ERROR                   2
#define SSH_DISCONNECT_KEY_EXCHANGE_FAILED              3
#define SSH_DISCONNECT_MAC_ERROR                        5
#define SSH_DISCONNECT_COMPRESSION_ERROR                6
#define SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            7
#define SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   8
#define SSH_DISCONNECT_CONNECTION_LOST                 10
#define SSH_DISCONNECT_BY_APPLICATION                  11
#define SSH_DISCONNECT_AUTH_CANCELLED_BY_USER          13

#endif
