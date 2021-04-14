#
# OpenWatcom makefile for SSH2DOS (real mode - large)
#

# Debug
#DEBUG=-d2

# uncomment this for B&W mode
COLOR = -DCOLOR

#################################################################
# In normal cases, no other settings should be changed below!!! #
#################################################################

CC = wcc
LINKER = wlink LibPath lib;$(%WATT_ROOT)\lib

CFLAGS = -zq -ml -0 -bt=dos -zt -s
CFLAGS += $(DEBUG) -i=$(%WATCOM)\h;include;$(%WATT_ROOT)\inc $(COLOR)
# -DMEMWATCH

.C.OBJ:	
        $(CC) $(CFLAGS) $[@

LIBS = lib\misc.lib lib\crypto.lib lib\ssh.lib lib\vt100.lib $(%WATT_ROOT)\lib\wattcpwl.lib lib\zlib_l.lib

all:    ssh2dos.exe sftpdos.exe scp2dos.exe telnet.exe

ssh2dos.exe : ssh2dos.obj $(LIBS)
	$(LINKER) @ssh2dos.lnk

sftpdos.exe : sftpdos.obj sftp.obj $(LIBS)
	$(LINKER) @sftpdos.lnk

scp2dos.exe : scpdos.obj $(LIBS)
	$(LINKER) @scp2dos.lnk

telnet.exe  : telnet.obj lib\misc.lib lib\vt100.lib $(%WATT_ROOT)\lib\wattcpwl.lib
	$(LINKER) @telnet.lnk

ttytest.exe : ttytest.obj $(LIBS)
	$(LINKER) @ttytest.lnk

lib\crypto.lib: sshrsa.obj sshdes.obj sshmd5.obj sshbn.obj sshpubk.obj int64.obj sshaes.obj  sshsha.obj sshsh512.obj sshdss.obj sshsh256.obj 
	wlib -b -c lib\crypto.lib -+sshrsa.obj -+sshdes.obj -+sshmd5.obj -+sshbn.obj -+sshpubk.obj
	wlib -b -c lib\crypto.lib -+int64.obj -+sshaes.obj -+sshsha.obj -+sshsh512.obj -+sshdss.obj -+sshsh256.obj

lib\ssh.lib: negotiat.obj transprt.obj auth.obj channel.obj
	wlib -b -c lib\ssh.lib -+negotiat.obj -+transprt.obj -+auth.obj -+channel.obj

lib\vt100.lib: vttio.obj vidio.obj keyio.obj keymap.obj
	wlib -b -c lib\vt100.lib -+vttio.obj -+vidio.obj -+keyio.obj -+keymap.obj

lib\misc.lib: common.obj shell.obj proxy.obj
	wlib -b -c lib\misc.lib -+common.obj -+shell.obj -+proxy.obj

clean: .SYMBOLIC
	del *.obj
	del *.map
	del lib\vt100.lib
	del lib\crypto.lib
	del lib\misc.lib
	del lib\ssh.lib
	del ssh2dos.exe
	del scp2dos.exe
	del sftpdos.exe
	del telnet.exe
	del ttytest.exe
