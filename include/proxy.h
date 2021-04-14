#ifndef _PROXY_H
#define _PROXY_H

#define NOPROXY		0
#define SOCKS_PROXY	1
#define HTTP_PROXY	2
#define SOCKS_PORT	1080
#define HTTP_PORT	3128

extern short socks5_connect(char *remotehost, unsigned short remoteport,
                            char *proxyuser, char *proxypass);

extern short http_connect(char *remotehost, unsigned short remoteport,
                            char *proxyuser, char *proxypass);

#endif
