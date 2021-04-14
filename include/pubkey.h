#ifndef _PUBKEY_H
#define _PUBKEY_H

enum { OSSH_DSA, OSSH_RSA };
struct openssh_key {
    int type;
    int encrypted;
    char iv[32];
    unsigned char *keyblob;
    int keyblob_len, keyblob_size;
};

struct ssh_signkey {
   unsigned char *(*public_blob) (void *, int *);
   void *(*createkey) (unsigned char *, int , unsigned char *, int);
   unsigned char *(*sign) (void *, char *, int, int *);
   char *name;
};

struct ssh2_userkey {
   const struct ssh_signkey *alg;     /* the key algorithm */
   void *data;			       /* the key data */
   char *comment;		       /* the key comment */
};

#define SSH2_WRONG_PASSPHRASE (&ssh2_wrong_passphrase)

int key_type(char *);
char *ssh2_userkey_loadpub(char *, char **, int *);
int ssh2_userkey_encrypted(char *, char **);
struct ssh2_userkey *ssh2_load_userkey(char *, char *);
int openssh_encrypted(char *);
struct ssh2_userkey *openssh_read(char *, char *);

char *key_type_to_str(int);

#endif
