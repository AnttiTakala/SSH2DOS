CC = wcc
LINK = wcl

CFLAGS = -ml -0 -fpi -bt=dos -s -i=$(%watcom)\h

all:	.SYMBOLIC
	@echo Please specify 'ssh1' or 'ssh2' as target

ssh1:	.SYMBOLIC
	$(CC) $(CFLAGS) -DSSHDOS ssh.c
	$(CC) $(CFLAGS) getopt.c
	$(CC) $(CFLAGS) regex.c
	$(LINK) -l=dos -fe=ssh.exe ssh.obj getopt.obj regex.obj

ssh2:	.SYMBOLIC
	$(CC) $(CFLAGS) -DSSH2DOS ssh.c
	$(CC) $(CFLAGS) getopt.c
	$(CC) $(CFLAGS) regex.c
	$(LINK) -l=dos -fe=ssh.exe ssh.obj getopt.obj regex.obj

clean: .SYMBOLIC
	del *.obj
	del *.err
	del ssh.exe
