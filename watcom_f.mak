#
# OpenWatcom makefile for SSH2DOS (protected mode version)
#

# Debug
#DEBUG=-d2

# uncomment this for B&W mode
COLOR = -DCOLOR

#################################################################
# In normal cases, no other settings should be changed below!!! #
#################################################################

CC = wcc386
LINKER = wlink LibPath lib;$(%WATT_ROOT)\lib

CFLAGS = -zq -mf -3r -s $(DEBUG) -i=$(%WATCOM)\h;.\include;$(%WATT_ROOT)\inc $(COLOR)
# -DMEMWATCH

.C.OBJ:	
        $(CC) $(CFLAGS) $[@

LIBS = lib\misc.lib lib\crypto.lib lib\ssh.lib lib\vt100.lib $(%WATT_ROOT)\lib\wattcpwf.lib lib\zlib_f.lib

all:    ssh2d386.exe sftpd386.exe scp2d386.exe tel386.exe

ssh2d386.exe : ssh2dos.obj $(LIBS)
	$(LINKER) @ssh2d386.lnk

sftpd386.exe : sftpdos.obj sftp.obj $(LIBS)
	$(LINKER) @sftpd386.lnk

scp2d386.exe : scpdos.obj $(LIBS)
	$(LINKER) @scp2d386.lnk

tel386.exe   : telnet.obj lib\misc.lib lib\vt100.lib $(%WATT_ROOT)\lib\wattcpwf.lib
	$(LINKER) @tel386.lnk

lib\crypto.lib: sshrsa.obj sshdes.obj sshmd5.obj sshbn.obj sshpubk.obj int64.obj sshaes.obj  sshsha.obj sshsh512.obj sshdss.obj
	wlib -b -c lib\crypto.lib -+sshrsa.obj -+sshdes.obj -+sshmd5.obj -+sshbn.obj -+sshpubk.obj
	wlib -b -c lib\crypto.lib -+int64.obj -+sshaes.obj -+sshsha.obj -+sshsh512.obj -+sshdss.obj

lib\ssh.lib: negotiat.obj transprt.obj auth.obj channel.obj
	wlib -b -c lib\ssh.lib -+negotiat.obj -+transprt.obj -+auth.obj -+channel.obj

lib\vt100.lib: vttio.obj vidio.obj keyio.obj keymap.obj
	wlib -b -c lib\vt100.lib -+vttio.obj -+vidio.obj -+keyio.obj -+keymap.obj

lib\misc.lib: common.obj shell.obj proxy.obj
	wlib -b -c lib\misc.lib  -+common.obj -+shell.obj -+proxy.obj

clean: .SYMBOLIC
	del *.obj
	del *.map
	del lib\vt100.lib
	del lib\crypto.lib
	del lib\misc.lib
	del lib\ssh.lib
	del ssh2d386.exe
	del sftpd386.exe
	del scp2d386.exe
	del tel386.exe
