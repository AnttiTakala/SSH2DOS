/*
 * Generic SSH public-key handling operations. In particular,
 * reading of SSH public-key files, and also the generic `sign'
 * operation for ssh2 (which checks the type of the key and
 * dispatches to the appropriate key-type specific function).
 *
 * Taken from the PuTTY source.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <ctype.h>

#include "ssh.h"
#include "pubkey.h"
#include "sshsha.h"
#include "sshmd5.h"
#include "macros.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

void des3_decrypt_pubkey_ossh(unsigned char *, unsigned char *,
			      unsigned char *, int);
void aes256_decrypt_pubkey(unsigned char *, unsigned char *, int);

extern const struct ssh_signkey ssh_dss;
extern const struct ssh_signkey ssh_rsa;

#define rsa_signature "SSH PRIVATE KEY FILE FORMAT 1.1\n"

/* ----------------------------------------------------------------------
 * SSH2 private key load/store functions.
 */

/*
 * PuTTY's own format for SSH2 keys is as follows:
 *
 * The file is text. Lines are terminated by CRLF, although CR-only
 * and LF-only are tolerated on input.
 *
 * The first line says "PuTTY-User-Key-File-2: " plus the name of the
 * algorithm ("ssh-dss", "ssh-rsa" etc).
 *
 * The next line says "Encryption: " plus an encryption type.
 * Currently the only supported encryption types are "aes256-cbc"
 * and "none".
 *
 * The next line says "Comment: " plus the comment string.
 *
 * Next there is a line saying "Public-Lines: " plus a number N.
 * The following N lines contain a base64 encoding of the public
 * part of the key. This is encoded as the standard SSH2 public key
 * blob (with no initial length): so for RSA, for example, it will
 * read
 *
 *    string "ssh-rsa"
 *    mpint  exponent
 *    mpint  modulus
 *
 * Next, there is a line saying "Private-Lines: " plus a number N,
 * and then N lines containing the (potentially encrypted) private
 * part of the key. For the key type "ssh-rsa", this will be
 * composed of
 *
 *    mpint  private_exponent
 *    mpint  p                  (the larger of the two primes)
 *    mpint  q                  (the smaller prime)
 *    mpint  iqmp               (the inverse of q modulo p)
 *    data   padding            (to reach a multiple of the cipher block size)
 *
 * And for "ssh-dss", it will be composed of
 *
 *    mpint  x                  (the private key parameter)
 *  [ string hash   20-byte hash of mpints p || q || g   only in old format ]
 * 
 * Finally, there is a line saying "Private-MAC: " plus a hex
 * representation of a HMAC-SHA-1 of:
 *
 *    string  name of algorithm ("ssh-dss", "ssh-rsa")
 *    string  encryption type
 *    string  comment
 *    string  public-blob
 *    string  private-plaintext (the plaintext version of the
 *                               private part, including the final
 *                               padding)
 * 
 * The key to the MAC is itself a SHA-1 hash of:
 * 
 *    data    "putty-private-key-file-mac-key"
 *    data    passphrase
 *
 * Encrypted keys should have a MAC, whereas unencrypted ones must
 * have a hash.
 *
 * If the key is encrypted, the encryption key is derived from the
 * passphrase by means of a succession of SHA-1 hashes. Each hash
 * is the hash of:
 *
 *    uint32  sequence-number
 *    data    passphrase
 *
 * where the sequence-number increases from zero. As many of these
 * hashes are used as necessary.
 *
 * For backwards compatibility with snapshots between 0.51 and
 * 0.52, we also support the older key file format, which begins
 * with "PuTTY-User-Key-File-1" (version number differs). In this
 * format the Private-MAC: field only covers the private-plaintext
 * field and nothing else (and without the 4-byte string length on
 * the front too). Moreover, for RSA keys the Private-MAC: field
 * can be replaced with a Private-Hash: field which is a plain
 * SHA-1 hash instead of an HMAC. This is not allowable in DSA
 * keys. (Yes, the old format was a mess. Guess why it changed :-)
 */

static int read_header(FILE * fp, char *header)
{
    int len = 39;
    int c;

    while (len > 0) {
	c = fgetc(fp);
	if (c == '\n' || c == '\r' || c == EOF)
	    return 0;		       /* failure */
	if (c == ':') {
	    c = fgetc(fp);
	    if (c != ' ')
		return 0;
	    *header = '\0';
	    return 1;		       /* success! */
	}
	if (len == 0)
	    return 0;		       /* failure */
	*header++ = c;
	len--;
    }
    return 0;			       /* failure */
}

static char *read_body(FILE * fp)
{
    char *text;
    int len;
    int size;
    int c;

    size = 128;
    if((text = malloc(size)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    len = 0;
    text[len] = '\0';

    while (1) {
	c = fgetc(fp);
	if (c == '\r' || c == '\n') {
	    c = fgetc(fp);
	    if (c != '\r' && c != '\n' && c != EOF)
		ungetc(c, fp);
	    return text;
	}
	if (c == EOF) {
	    free(text);
	    return NULL;
	}
	if (len + 1 > size) {
	    size += 128;
	    if((text = realloc(text, size)) == NULL)
               fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	}
	text[len++] = c;
	text[len] = '\0';
    }
}

int base64_decode_atom(char *atom, unsigned char *out)
{
    unsigned long vals[4], v;
    int i, len;
    unsigned long word;
    char c;

    for (i = 0; i < 4; i++) {
	c = atom[i];
	if (c >= 'A' && c <= 'Z')
	    v = c - 'A';
	else if (c >= 'a' && c <= 'z')
	    v = c - 'a' + 26;
	else if (c >= '0' && c <= '9')
	    v = c - '0' + 52;
	else if (c == '+')
	    v = 62;
	else if (c == '/')
	    v = 63;
	else if (c == '=')
	    v = -1;
	else
	    return 0;		       /* invalid atom */
	vals[i] = v;
    }

    if (vals[0] == -1 || vals[1] == -1)
	return 0;
    if (vals[2] == -1 && vals[3] != -1)
	return 0;

    if (vals[3] != -1)
	len = 3;
    else if (vals[2] != -1)
	len = 2;
    else
	len = 1;

    word = ((vals[0] << 18) |
	    (vals[1] << 12) | ((vals[2] & 0x3F) << 6) | (vals[3] & 0x3F));
    out[0] = (word >> 16) & 0xFF;
    if (len > 1)
	out[1] = (word >> 8) & 0xFF;
    if (len > 2)
	out[2] = word & 0xFF;
    return len;
}

static char *read_blob(FILE * fp, int nlines, int *bloblen)
{
    unsigned char *blob;
    char *line;
    int linelen, len;
    int i, j, k;

    /* We expect at most 64 base64 characters, ie 48 real bytes, per line. */
    if((blob = malloc(48 * nlines)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    len = 0;
    for (i = 0; i < nlines; i++) {
	line = read_body(fp);
	if (!line) {
	    free(blob);
	    return NULL;
	}
	linelen = strlen(line);
	if (linelen % 4 != 0 || linelen > 64) {
	    free(blob);
	    free(line);
	    return NULL;
	}
	for (j = 0; j < linelen; j += 4) {
	    k = base64_decode_atom(line + j, blob + len);
	    if (!k) {
		free(line);
		free(blob);
		return NULL;
	    }
	    len += k;
	}
	free(line);
    }
    *bloblen = len;
    return blob;
}

/*
 * Magic error return value for when the passphrase is wrong.
 */
struct ssh2_userkey ssh2_wrong_passphrase = {
    NULL, NULL, NULL
};

struct ssh2_userkey *ssh2_load_userkey(char *filename, char *passphrase)
{
    FILE *fp;
    char header[40], *b, *encryption = NULL, *comment, *mac;
    unsigned char key[40];
    const struct ssh_signkey *alg;
    struct ssh2_userkey *ret;
    int cipher, cipherblk;
    unsigned char *public_blob, *private_blob;
    int public_blob_len, private_blob_len;
    int i, is_mac;
    int passlen = passphrase ? strlen(passphrase) : 0;

    ret = NULL;			       /* return NULL for most errors */
    comment = mac = NULL;
    public_blob = private_blob = NULL;

    fp = fopen(filename, "rb");
    if (!fp)
	goto error;

    /* Read the first header line which contains the key type. */
    if (!read_header(fp, header))
	goto error;
    if (0 == strcmp(header, "PuTTY-User-Key-File-2"));
    else
	goto error;
    if ((b = read_body(fp)) == NULL)
	goto error;
    /* Select key algorithm structure. */
    if (!strcmp(b, "ssh-rsa"))
	alg = &ssh_rsa;
    else if (!strcmp(b, "ssh-dss"))
	alg = &ssh_dss;
    else {
	free(b);
	goto error;
    }
    free(b);

    /* Read the Encryption header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Encryption"))
	goto error;
    if ((encryption = read_body(fp)) == NULL)
	goto error;
    if (!strcmp(encryption, "aes256-cbc")) {
	cipher = 1;
	cipherblk = 16;
    } else if (!strcmp(encryption, "none")) {
	cipher = 0;
	cipherblk = 1;
    } else {
	free(encryption);
	goto error;
    }

    /* Read the Comment header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Comment"))
	goto error;
    if ((comment = read_body(fp)) == NULL)
	goto error;

    /* Read the Public-Lines header line and the public blob. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Public-Lines"))
	goto error;
    if ((b = read_body(fp)) == NULL)
	goto error;
    i = atoi(b);
    free(b);
    if ((public_blob = read_blob(fp, i, &public_blob_len)) == NULL)
	goto error;

    /* Read the Private-Lines header line and the Private blob. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Private-Lines"))
	goto error;
    if ((b = read_body(fp)) == NULL)
	goto error;
    i = atoi(b);
    free(b);
    if ((private_blob = read_blob(fp, i, &private_blob_len)) == NULL)
	goto error;

    /* Read the Private-MAC or Private-Hash header line. */
    if (!read_header(fp, header))
	goto error;
    if (0 == strcmp(header, "Private-MAC")) {
	if ((mac = read_body(fp)) == NULL)
	    goto error;
	is_mac = 1;
    }
    else
	goto error;

    fclose(fp);
    fp = NULL;

    /*
     * Decrypt the private blob.
     */
    if (cipher) {
	SHA_State s;

	if (!passphrase)
	    goto error;
	if (private_blob_len % cipherblk)
	    goto error;

	SHA_Init(&s);
	SHA_Bytes(&s, "\0\0\0\0", 4);
	SHA_Bytes(&s, passphrase, passlen);
	SHA_Final(&s, key + 0);
	SHA_Init(&s);
	SHA_Bytes(&s, "\0\0\0\1", 4);
	SHA_Bytes(&s, passphrase, passlen);
	SHA_Final(&s, key + 20);
	aes256_decrypt_pubkey(key, private_blob, private_blob_len);
    }

    /*
     * Verify the MAC.
     */
    {
	char realmac[41];
	unsigned char binary[20];
	unsigned char *macdata;
	int maclen;
	int free_macdata;

	unsigned char *p;
	int namelen = strlen(alg->name);
	int enclen = strlen(encryption);
	int commlen = strlen(comment);
	maclen = (4 + namelen +
		      4 + enclen +
		      4 + commlen +
		      4 + public_blob_len +
		      4 + private_blob_len);
	if((macdata = malloc(maclen)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	p = macdata;
#define DO_STR(s,len) PUT_32BIT_MSB_FIRST(p,(len));memcpy(p+4,(s),(len));p+=4+(len)
	DO_STR(alg->name, namelen);
	DO_STR(encryption, enclen);
	DO_STR(comment, commlen);
	DO_STR(public_blob, public_blob_len);
	DO_STR(private_blob, private_blob_len);

	free_macdata = 1;

	if (is_mac) {
	    SHA_State s;
	    unsigned char mackey[20];
	    char header[] = "putty-private-key-file-mac-key";

	    SHA_Init(&s);
	    SHA_Bytes(&s, header, sizeof(header)-1);
	    if (passphrase)
		SHA_Bytes(&s, passphrase, passlen);
	    SHA_Final(&s, mackey);

	    hmac_sha1_simple(mackey, 20, macdata, maclen, binary);

	    memset(mackey, 0, sizeof(mackey));
	    memset(&s, 0, sizeof(s));
	} else {
	    SHA_Simple(macdata, maclen, binary);
	}

	if (free_macdata) {
	    memset(macdata, 0, maclen);
	    free(macdata);
	}

	for (i = 0; i < 20; i++)
	    sprintf(realmac + 2 * i, "%02x", binary[i]);

	if (strcmp(mac, realmac)) {
	    /* An incorrect MAC is an unconditional Error if the key is
	     * unencrypted. Otherwise, it means Wrong Passphrase. */
	    ret = cipher ? SSH2_WRONG_PASSPHRASE : NULL;
	    goto error;
	}
    }
    free(mac);

    /*
     * Create and return the key.
     */
    if((ret = malloc(sizeof(struct ssh2_userkey))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    ret->alg = alg;
    ret->comment = comment;
    ret->data = alg->createkey(public_blob, public_blob_len,
			       private_blob, private_blob_len);
    if (!ret->data) {
	free(ret->comment);
	free(ret);
	ret = NULL;
    }
    free(public_blob);
    free(private_blob);
    free(encryption);
    return ret;

    /*
     * Error processing.
     */
  error:
    if (fp)
	fclose(fp);
    if (comment)
	free(comment);
    if (encryption)
	free(encryption);
    if (mac)
	free(mac);
    if (public_blob)
	free(public_blob);
    if (private_blob)
	free(private_blob);
    return ret;
}

int ssh2_userkey_encrypted(char *filename, char **commentptr)
{
    FILE *fp;
    char header[40], *b, *comment;
    int ret;

    if (commentptr)
	*commentptr = NULL;

    fp = fopen(filename, "rb");
    if (!fp)
	return 0;
    if (!read_header(fp, header)
	|| (0 != strcmp(header, "PuTTY-User-Key-File-2") &&
	    0 != strcmp(header, "PuTTY-User-Key-File-1"))) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }
    free(b);			       /* we don't care about key type here */
    /* Read the Encryption header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Encryption")) {
	fclose(fp);
	return 0;
    }
    if ((b = read_body(fp)) == NULL) {
	fclose(fp);
	return 0;
    }

    /* Read the Comment header line. */
    if (!read_header(fp, header) || 0 != strcmp(header, "Comment")) {
	fclose(fp);
	free(b);
	return 1;
    }
    if ((comment = read_body(fp)) == NULL) {
	fclose(fp);
	free(b);
	return 1;
    }

    if (commentptr)
	*commentptr = comment;

    fclose(fp);
    if (!strcmp(b, "aes256-cbc"))
	ret = 1;
    else
	ret = 0;
    free(b);
    return ret;
}

/* OpenSSH */

#define isbase64(c) (    ((c) >= 'A' && (c) <= 'Z') || \
                         ((c) >= 'a' && (c) <= 'z') || \
                         ((c) >= '0' && (c) <= '9') || \
                         (c) == '+' || (c) == '/' || (c) == '=' \
                         )

static int ber_read_id_len(void *source, int sourcelen,
		    int *id, int *length, int *flags)
{
    unsigned char *p = (unsigned char *) source;

    if (sourcelen == 0)
	return -1;

    *flags = (*p & 0xE0);
    if ((*p & 0x1F) == 0x1F) {
	*id = 0;
	while (*p & 0x80) {
	    *id = (*id << 7) | (*p & 0x7F);
	    p++, sourcelen--;
	    if (sourcelen == 0)
		return -1;
	}
	*id = (*id << 7) | (*p & 0x7F);
	p++, sourcelen--;
    } else {
	*id = *p & 0x1F;
	p++, sourcelen--;
    }

    if (sourcelen == 0)
	return -1;

    if (*p & 0x80) {
	int n = *p & 0x7F;
	p++, sourcelen--;
	if (sourcelen < n)
	    return -1;
	*length = 0;
	while (n--)
	    *length = (*length << 8) | (*p++);
	sourcelen -= n;
    } else {
	*length = *p;
	p++, sourcelen--;
    }

    return p - (unsigned char *) source;
}

struct openssh_key *load_openssh_key(char *filename)
{
    struct openssh_key *ret;
    FILE *fp;
    char buffer[256];
    char *p;
    int headers_done;
    char base64_bit[4];
    int base64_chars = 0;

    if((ret = malloc(sizeof(*ret))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    ret->keyblob = NULL;
    ret->keyblob_len = ret->keyblob_size = 0;
    ret->encrypted = 0;
    memset(ret->iv, 0, sizeof(ret->iv));

    fp = fopen(filename, "r");
    if (!fp) {
	/* "Unable to open key file" */
	goto error;
    }
    if (!fgets(buffer, sizeof(buffer), fp) ||
	0 != strncmp(buffer, "-----BEGIN ", 11) ||
	0 != strcmp(buffer+strlen(buffer)-17, "PRIVATE KEY-----\n")) {
	/* "File does not begin with OpenSSH key header" */
	goto error;
    }
    if (!strcmp(buffer, "-----BEGIN RSA PRIVATE KEY-----\n"))
	ret->type = OSSH_RSA;
    else if (!strcmp(buffer, "-----BEGIN DSA PRIVATE KEY-----\n"))
	ret->type = OSSH_DSA;
    else {
	/* "Unrecognised key type" */
	goto error;
    }

    headers_done = 0;
    while (1) {
	if (!fgets(buffer, sizeof(buffer), fp)) {
	    /* "Unexpected end of file" */
	    goto error;
	}
	if (0 == strncmp(buffer, "-----END ", 9) &&
	    0 == strcmp(buffer+strlen(buffer)-17, "PRIVATE KEY-----\n"))
	    break;		       /* done */
	if ((p = strchr(buffer, ':')) != NULL) {
	    if (headers_done) {
		/* "Header found in body of key data" */
		goto error;
	    }
	    *p++ = '\0';
	    while (*p && isspace((unsigned char)*p)) p++;
	    if (!strcmp(buffer, "Proc-Type")) {
		if (p[0] != '4' || p[1] != ',') {
		    /* "Proc-Type is not 4 (only 4 is supported)" */
		    goto error;
		}
		p += 2;
		if (!strcmp(p, "ENCRYPTED\n"))
		    ret->encrypted = 1;
	    } else if (!strcmp(buffer, "DEK-Info")) {
		int i, j;

		if (strncmp(p, "DES-EDE3-CBC,", 13)) {
		    /* "Ciphers other than DES-EDE3-CBC not supported" */
		    goto error;
		}
		p += 13;
		for (i = 0; i < 8; i++) {
		    if (1 != sscanf(p, "%2x", &j))
			break;
		    ret->iv[i] = j;
		    p += 2;
		}
		if (i < 8) {
		    /* "Expected 16-digit iv in DEK-Info" */
		    goto error;
		}
	    }
	} else {
	    headers_done = 1;

	    p = buffer;
	    while (isbase64(*p)) {
                base64_bit[base64_chars++] = *p;
                if (base64_chars == 4) {
                    unsigned char out[3];
                    int len;

                    base64_chars = 0;

                    len = base64_decode_atom(base64_bit, out);

                    if (len <= 0) {
                        /* "Invalid base64 encoding" */
                        goto error;
                    }

                    if (ret->keyblob_len + len > ret->keyblob_size) {
                        ret->keyblob_size = ret->keyblob_len + len + 256;
                        if((ret->keyblob = realloc(ret->keyblob, ret->keyblob_size)) == NULL)
                           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
                    }

                    memcpy(ret->keyblob + ret->keyblob_len, out, len);
                    ret->keyblob_len += len;

                    memset(out, 0, sizeof(out));
                }

		p++;
	    }
	}
    }

    if (ret->keyblob_len == 0 || !ret->keyblob) {
	/* "Key body not present" */
	goto error;
    }

    if (ret->encrypted && ret->keyblob_len % 8 != 0) {
	/* "Encrypted key blob is not a multiple of cipher block size" */
	goto error;
    }

    memset(buffer, 0, sizeof(buffer));
    memset(base64_bit, 0, sizeof(base64_bit));
    return ret;

    error:
    memset(buffer, 0, sizeof(buffer));
    memset(base64_bit, 0, sizeof(base64_bit));
    if (ret) {
	if (ret->keyblob) {
            memset(ret->keyblob, 0, ret->keyblob_size);
            free(ret->keyblob);
        }
        memset(&ret, 0, sizeof(ret));
	free(ret);
    }
    return NULL;
}

int openssh_encrypted(char *filename)
{
    struct openssh_key *key = load_openssh_key(filename);
    int ret;

    if (!key)
	return 0;
    ret = key->encrypted;
    memset(key->keyblob, 0, key->keyblob_size);
    free(key->keyblob);
    memset(&key, 0, sizeof(key));
    free(key);
    return ret;
}

struct ssh2_userkey *openssh_read(char *filename, char *passphrase)
{
    struct openssh_key *key;
    struct ssh2_userkey *retkey;
    unsigned char *p;
    int ret, id, len, flags;
    int i, num_integers;
    struct ssh2_userkey *retval = NULL;
    unsigned char *blob;
    int blobsize = 0, blobptr, privptr;
    char *modptr = NULL;
    int modlen = 0;

    key = load_openssh_key(filename);

    blob = NULL;

    if (!key)
	return NULL;

    if (key->encrypted) {
	/*
	 * Derive encryption key from passphrase and iv/salt:
	 * 
	 *  - let block A equal MD5(passphrase || iv)
	 *  - let block B equal MD5(A || passphrase || iv)
	 *  - block C would be MD5(B || passphrase || iv) and so on
	 *  - encryption key is the first N bytes of A || B
	 */
	unsigned char keybuf[32];

	MD5Init();
	MD5Update(passphrase, strlen(passphrase));
	MD5Update(key->iv, 8);
	MD5Final(keybuf);

	MD5Init();
	MD5Update(keybuf, 16);
	MD5Update(passphrase, strlen(passphrase));
	MD5Update(key->iv, 8);
	MD5Final(keybuf+16);

	/*
	 * Now decrypt the key blob.
	 */
	des3_decrypt_pubkey_ossh(keybuf, key->iv,
				 key->keyblob, key->keyblob_len);

        memset(keybuf, 0, sizeof(keybuf));
    }

    /*
     * Now we have a decrypted key blob, which contains an ASN.1
     * encoded private key. We must now untangle the ASN.1.
     *
     * We expect the whole key blob to be formatted as a SEQUENCE
     * (0x30 followed by a length code indicating that the rest of
     * the blob is part of the sequence). Within that SEQUENCE we
     * expect to see a bunch of INTEGERs. What those integers mean
     * depends on the key type:
     *
     *  - For RSA, we expect the integers to be 0, n, e, d, p, q,
     *    dmp1, dmq1, iqmp in that order. (The last three are d mod
     *    (p-1), d mod (q-1), inverse of q mod p respectively.)
     *
     *  - For DSA, we expect them to be 0, p, q, g, y, x in that
     *    order.
     */
    
    p = key->keyblob;

    /* Expect the SEQUENCE header. Take its absence as a failure to decrypt. */
    ret = ber_read_id_len(p, key->keyblob_len, &id, &len, &flags);
    p += ret;
    if (ret < 0 || id != 16) {
	/* "ASN.1 decoding failure" */
	retval = SSH2_WRONG_PASSPHRASE;
	goto error;
    }

    /* Expect a load of INTEGERs. */
    if (key->type == OSSH_RSA)
	num_integers = 9;
    else
	num_integers = 6;

    /*
     * Space to create key blob in.
     */
    blobsize = 256+key->keyblob_len;
    if((blob = malloc(blobsize)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    PUT_32BIT_MSB_FIRST(blob, 7);
    if (key->type == OSSH_DSA)
	memcpy(blob+4, "ssh-dss", 7);
    else
	memcpy(blob+4, "ssh-rsa", 7);
    blobptr = 4+7;
    privptr = -1;

    for (i = 0; i < num_integers; i++) {
	ret = ber_read_id_len(p, key->keyblob+key->keyblob_len-p,
			      &id, &len, &flags);
	p += ret;
	if (ret < 0 || id != 2 ||
	    key->keyblob+key->keyblob_len-p < len) {
	    /* "ASN.1 decoding failure" */
	    goto error;
	}

	if (i == 0) {
	    /*
	     * The first integer should be zero always (I think
	     * this is some sort of version indication).
	     */
	    if (len != 1 || p[0] != 0) {
		/* "Version number mismatch" */
		goto error;
	    }
	} else if (key->type == OSSH_RSA) {
	    /*
	     * Integers 1 and 2 go into the public blob but in the
	     * opposite order; integers 3, 4, 5 and 8 go into the
	     * private blob. The other two (6 and 7) are ignored.
	     */
	    if (i == 1) {
		/* Save the details for after we deal with number 2. */
		modptr = p;
		modlen = len;
	    } else if (i != 6 && i != 7) {
		PUT_32BIT_MSB_FIRST(blob+blobptr, len);
		memcpy(blob+blobptr+4, p, len);
		blobptr += 4+len;
		if (i == 2) {
		    PUT_32BIT_MSB_FIRST(blob+blobptr, modlen);
		    memcpy(blob+blobptr+4, modptr, modlen);
		    blobptr += 4+modlen;
		    privptr = blobptr;
		}
	    }
	} else {
	    /*
	     * Integers 1-4 go into the public blob; integer 5 goes
	     * into the private blob.
	     */
	    PUT_32BIT_MSB_FIRST(blob+blobptr, len);
	    memcpy(blob+blobptr+4, p, len);
	    blobptr += 4+len;
	    if (i == 4)
		privptr = blobptr;
	}

	/* Skip past the number. */
	p += len;
    }

    /*
     * Now put together the actual key. Simplest way to do this is
     * to assemble our own key blobs and feed them to the createkey
     * functions; this is a bit faffy but it does mean we get all
     * the sanity checks for free.
     */
    assert(privptr > 0);	       /* should have bombed by now if not */
    if((retkey = malloc(sizeof(struct ssh2_userkey))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
    retkey->alg = (key->type == OSSH_RSA ? &ssh_rsa : &ssh_dss);
    retkey->data = retkey->alg->createkey(blob, privptr,
					  blob+privptr, blobptr-privptr);
    if (!retkey->data) {
	free(retkey);
	/* "unable to create key data structure" */
	goto error;
    }

    retkey->comment = strdup("imported-openssh-key");
    retval = retkey;

    error:
    if (blob) {
        memset(blob, 0, blobsize);
        free(blob);
    }
    memset(key->keyblob, 0, key->keyblob_size);
    free(key->keyblob);
    memset(&key, 0, sizeof(key));
    free(key);
    return retval;
}



/* ----------------------------------------------------------------------
 * A function to determine the type of a private key file. Returns
 * 0 on failure, 1 or 2 on success.
 */
int key_type(char *filename)
{
    FILE *fp;
    char buf[32];
    const char putty2_sig[] = "PuTTY-User-Key-File-";
    const char sshcom_sig[] = "---- BEGIN SSH2 ENCRYPTED PRIVAT";
    const char openssh_sig[] = "-----BEGIN ";
    int i;

    fp = fopen(filename, "r");
    if (!fp)
	return SSH_KEYTYPE_UNOPENABLE;
    i = fread(buf, 1, sizeof(buf), fp);
    fclose(fp);
    if (i < 0)
	return SSH_KEYTYPE_UNOPENABLE;
    if (i < 32)
	return SSH_KEYTYPE_UNKNOWN;
    if (!memcmp(buf, rsa_signature, sizeof(rsa_signature)-1))
	return SSH_KEYTYPE_SSH1;
    if (!memcmp(buf, putty2_sig, sizeof(putty2_sig)-1))
	return SSH_KEYTYPE_SSH2;
    if (!memcmp(buf, openssh_sig, sizeof(openssh_sig)-1))
	return SSH_KEYTYPE_OPENSSH;
    if (!memcmp(buf, sshcom_sig, sizeof(sshcom_sig)-1))
	return SSH_KEYTYPE_SSHCOM;
    return SSH_KEYTYPE_UNKNOWN;	       /* unrecognised or EOF */
}

/*
 * Convert the type word to a string, for `wrong type' error
 * messages.
 */
char *key_type_to_str(int type)
{
    switch (type) {
      case SSH_KEYTYPE_UNOPENABLE:
	return "unable to open file";

      case SSH_KEYTYPE_UNKNOWN:
	return "not a private key";

      case SSH_KEYTYPE_SSH1:
	return "SSH1 private key";

      case SSH_KEYTYPE_SSH2:
	return "PuTTY SSH2 private key";

      case SSH_KEYTYPE_OPENSSH:
	return "OpenSSH SSH2 private key";

      case SSH_KEYTYPE_SSHCOM:
	return "ssh.com SSH2 private key";

      default:
	return "INTERNAL ERROR";
    }
}
