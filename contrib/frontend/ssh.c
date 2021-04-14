/*
 *	Frontend to sshdos
 *	Reads options and config file and calls sshdos appropriately.
 *	GPLed by Ken Yap, 2000
 *
 *  $Date: 2005/12/31 10:11:33 $
 *  $Revision: 1.3 $
 *
 *		2000-08-30
 *		2000-08-30	Added regex matching for hostnames
 *		2000-08-31	Use __TURBOC__ so tc2.0 can compile
 *				Undef DEBUGs to silence most output
 *		2000-09-02	Add -t option
 *				Handle null user: @host sanely
 *		2000-09-21	Slightly modified by Nagy Daniel:
 *				  added 'Term' option to config file
 *		2000-10-16	Pass trailing args to sshdos so that
 *				they can be treated as command args
 *		2001-04-04	Added -s option
 *		2002-02-11	Added -n and -k option
 *		2002-03-21	Added -C option
 *		2003-05-20	Added -m option
 *		2003-11-05	OpenWatcom port (removed DJGPP and BORLAND)
 *		2003-11-26	Support for separate SSH1 and SSh2 port
 *				  added 'Mode' option to config file
 *				  added -g option
 *
 *	Need to fix: Host lines can have more than one value
 */

#undef		DEBUG_CONFIG
#undef		DEBUG_REGEX
#define		DEBUG_EXEC

#include	<stdio.h>
#include	<stdlib.h>
#include	<string.h>
#include	<ctype.h>
#include	<process.h>
#include	"getopt.h"
#define	strcasecmp(a,b)	stricmp(a,b)

#include	"regex.h"

/*#define	SYSCONFDIR	"\\etc"		*/
#if defined (SSHDOS)
 #define		USERCONFIGFILE	"ssh1.cfg"
#elif defined (SSH2DOS)
 #define		USERCONFIGFILE	"ssh2.cfg"
#endif

char		*sysconfigfile;

#if defined (SSHDOS)
 char		*cipher = 0;
#elif defined (SSH2DOS)
 int		dhgroup = 0;
#endif
char		*user = 0;
char		*port = 0;
char		*host = 0;
char		*term = 0;
char		*vidmode = 0;
char            *keymap = 0;
char		*mode = 0;
int		privport = -1;
int		supressstatus = 0;
int		compression = 0;
int		addCR = 0;
char		*password = 0;

int		newargc = 0;
char		*newargv[32];	/* make sure this is enough for all new args */
#define	NARGS	(sizeof(newargv)/sizeof(newargv[0]))

void		scanconfig(const char *file, char *host);
void		dumpargv(char *argv[]);

#ifdef		SCP_FRONTEND
int main(int argc, char **argv)
{
	printf("scp frontend not ready\n");
	exit(0);
}
#else
int main(int argc, char **argv)
{
	int		c, i, j;
	char		*p;
	extern int	optind;
	extern char	*optarg;

#ifdef	SYSCONFDIR
	sysconfigfile = SYSCONFDIR "\\USERCONFIGFILE";
#else
	/* overestimate, but play safe, not dependent on name of executable */
	sysconfigfile = malloc(strlen(argv[0]) + sizeof("\\USERCONFIGFILE"));
	if (sysconfigfile == 0)		/* out of memory!? */
		exit(1);
	strcpy(sysconfigfile, argv[0]);
	if ((p = strrchr(sysconfigfile, '\\')) == 0)
		p = sysconfigfile;
	strcpy(p, "\\USERCONFIGFILE");
#endif
#if defined (SSHDOS)
	while ((c = getopt(argc, argv, "c:l:p:s:t:k:PSCn")) != EOF) {
#elif defined (SSH2DOS)
	while ((c = getopt(argc, argv, "l:p:s:t:k:gPSCn")) != EOF) {
#endif
		switch (c) {
#if defined (SSHDOS)
		case 'c':
			cipher = optarg;
			break;
#elif defined (SSH2DOS)
		case 'g':
			dhgroup = 1;
			break;
#endif
		case 'l':
			user = optarg;
			break;
		case 'p':
			port = optarg;
			break;
		case 's':
			password = optarg;
			break;
		case 't':
			term = optarg;
			break;
		case 'k':
			keymap = optarg;
			break;
		case 'm':
			mode = optarg;
			break;
		case 'P':
			privport = 1;
			break;
                case 'S':
                        supressstatus = 1;
                        break;

                case 'C':
                        compression = 1;
                        break;

                case 'n':
                        addCR = 1;
                        break;

		default:
			fprintf(stderr, "Unknown option %c\n", c);
			break;
		}
	}
	argc -= optind;
	argv += optind;
	if (argc <= 0) {
		fprintf(stderr, "Usage: ssh [options] host|user@host [command [args]]\n");
		exit(1);
	}
	host = argv[0];
	argv++; argc--;
	if ((p = strchr(host, '@')) != 0) {
		user = host;
		*p = '\0';		/* user@host will override -l user */
		if (*user == '\0')
			user = 0;	/* simplify to one case */
		host = p + 1;
	}
	scanconfig(USERCONFIGFILE, host);
	scanconfig(sysconfigfile, host);
#if defined (SSHDOS)
 #if defined (SSH386)
	newargv[0] = "sshd386";
 #else
	newargv[0] = "sshdos";
 #endif
#elif defined (SSH2DOS)
 #if defined (SSH386)
	newargv[0] = "ssh2d386";
 #else
	newargv[0] = "ssh2dos";
 #endif
#endif
	i = 1;
#if defined (SSHDOS)
	if (cipher) {
		newargv[i++] = "-c";
		newargv[i++] = cipher;
	}
#elif defined (SSH2DOS)
	if (dhgroup)
                newargv[i++] = "-g";
#endif

	if (port) {
		newargv[i++] = "-p";
		newargv[i++] = port;
	}
	if (password) {
		newargv[i++] = "-s";
		newargv[i++] = password;
	}
	if (term) {
		newargv[i++] = "-t";
		newargv[i++] = term;
	}
	if (keymap) {
		newargv[i++] = "-k";
		newargv[i++] = keymap;
	}
	if (mode) {
		newargv[i++] = "-m";
		newargv[i++] = mode;
	}
	if (privport > 0)
		newargv[i++] = "-P";
        if (supressstatus)
                newargv[i++] = "-S";
        if (compression)
                newargv[i++] = "-C";
        if (addCR)
                newargv[i++] = "-n";
	if (user)
		newargv[i++] = user;
	newargv[i++] = host;
	/* append command args if any */
	for (j = 0; i < NARGS - 1 && j < argc; j++)
		newargv[i++] = argv[j];
	newargv[i] = 0;
#ifdef	DEBUG_EXEC
	dumpargv(newargv);
#endif
#if defined (SSHDOS)
 #if defined (SSH386)
	execvp("sshd386", newargv);
	perror("sshd386");
 #else
	execvp("sshdos", newargv);
	perror("sshdos");
 #endif
#elif defined (SSH2DOS)
 #if defined (SSH386)
	execvp("ssh2d386", newargv);
	perror("ssh2d386");
 #else
	execvp("ssh2dos", newargv);
	perror("ssh2dos");
 #endif
#endif
	return(0);
}
#endif	/* SCP_FRONTEND */

/*
 *	Read up to bufsiz-1 characters from line
 *	discarding excess until \n or EOF.
 *	Terminates string with \0
 */
char *getline(FILE *f, char *buffer, int bufsiz) {
	int		c;
	char		*p = buffer;

	while ((c = fgetc(f)) != EOF && c != '\n') {
		if (c == '\r')
			continue;
		if (p != &buffer[bufsiz-1])
			*p++ = c;
	}
	*p = '\0';
	return (c == EOF ? NULL : buffer);
}

int iscomment(const char *line)
{
	while (isspace(*line))
		line++;
	return (*line == '\0' || *line == '#');
}

int splitline(char *line, char **key, char **value)
{
	char		*keyend;

	while (isspace(*line))
		line++;
	if (*line == '\0')
		return (0);
	*key = line;
	while (*line != '\0' && !isspace(*line))
		line++;
	if (*line == '\0')
		return (0);
	keyend = line;		/* save end position */
	while (isspace(*line))
		line++;
	if (*line == '\0')
		return (0);
	*value = line;
	while (*line != '\0' && !isspace(*line))
		line++;
	*keyend = '\0';		/* terminate key argument */
	*line = '\0';		/* terminate value argument */
	return (1);
}

int matchname(char *host, char *pattern)
{
	char		*pat, *p, *q;
	int		i;

	if ((pat = malloc(strlen(pattern)*2+2)) == 0)	/* twice and ^$ */
		return (0);	/* no free space */
	/* convert primitive ssh host patern to what re_comp wants */
	p = pat;
	*p++ = '^';		/* put BOL at beginning */
	for (q = pattern; *q != '\0'; p++, q++) {
		if (strchr(".\\[]+^$", *q) != 0)	/* escape these */
			*p++ = '\\';
		else if (*q == '*')
			*p++ = '.';			/* * -> .* */
		else if (*q == '?') {			/* ? -> . */
			*p++ = '.';
			continue;
		}
		*p = *q;
	}
	*p++ = '$';		/* put EOL at end */
	*p = '\0';
#ifdef	DEBUG_REGEX
	printf("regex: %s\n", pat);
#endif
	if ((p = re_comp(pat)) != NULL){/* not reentrant, NFA is static data */
		fprintf(stderr, "re_comp: %s\n", p);
		free(pat);
		return (0);
	}
	i = re_exec(host);
	free(pat);
	return (i == 1);	/* 0 -> fail, -1 -> error */
}

void setvalue(const char *key, const char *value)
{
	if (strcasecmp(key, "Hostname") == 0) {
		host = strdup(value);		/* overwrite hostname */
	} else if (strcasecmp(key, "Port") == 0) {
		if (port == 0)		/* only if no -p port */
			port = strdup(value);
	}
#if defined (SSHDOS)
          else if (strcasecmp(key, "Cipher") == 0) {
		if (cipher == 0)	/* only if no -c cipher */
			cipher = strdup(value);
	}
#endif
          else if (strcasecmp(key, "Term") == 0) {
		if (term == 0)	/* only if no -t terminal */
			term = strdup(value);
	} else if (strcasecmp(key, "Keymap") == 0) {
		if (keymap == 0)/* only if no -k keymap */
			keymap = strdup(value);
	} else if (strcasecmp(key, "Mode") == 0) {
		if (mode == 0)/* only if no -m mode */
			mode = strdup(value);
	} else if (strcasecmp(key, "User") == 0) {
		if (user == 0)		/* only if no user specified */
			user = strdup(value);
	} else if (strcasecmp(key, "UsePrivilegedPort") == 0) {
		if (privport < 0)	/* only if no -P */
			privport = strcmp(value, "yes") == 0 ? 1 :
				strcmp(value, "no") ? 0 : -1;
	}
}

void scanconfig(const char *file, char *host)
{
	FILE		*f;
	int		sectionmatches = 0;
	char		line[256];
	char		*key, *value;

	if ((f = fopen(file, "r")) == NULL)
		return;
	while (getline(f, line, sizeof(line)) != NULL) {
		if (iscomment(line))
			continue;
		if (splitline(line, &key, &value) == 0)
			continue;
#ifdef	DEBUG_CONFIG
		printf("%s=%s\n", key, value);
#endif
		if (strcasecmp(key, "Host") == 0) {
			sectionmatches = matchname(host, value);
			continue;
		}
		if (!sectionmatches)
			continue;
		setvalue(key, value);
	}
	fclose(f);
}

void dumpargv(char *argv[])
{
	char		*p;

	printf("Command:");
	for (p = *argv++; p != 0; p = *argv++)
		printf(" %s", p);
	printf("\n");
}
