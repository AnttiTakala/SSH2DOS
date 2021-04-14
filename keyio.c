/* Copyright (c) 1988 Jerry Joplin
 *
 * Portions copyright (c) 1981, 1988
 * Trustees of Columbia University in the City of New York
 *
 * Permission is granted to any individual or institution
 * to use, copy, or redistribute this program and
 * documentation as long as it is not sold for profit and
 * as long as the Columbia copyright notice is retained.
 *
 *
 * Modified by Nagy Daniel - terminal emulation fixes
 */

#include <stdio.h>
#include <bios.h>
#include <string.h>

#include "config.h"
#include "channel.h"
#include "common.h"
#include "common.h"
#include "shell.h"
#include "vidio.h"
#include "keymap.h"

#define ESC	    0x1B	/* ASCII ESCape character */
#define DEL         0x7F	/* ASCII DELete character */
#define BKSP        0x0E08	/* BacKSPace scan code */
#define F1          0x3B00	/* Function key 1 scan code */
#define F2          0x3C00	/* Function key 2 scan code */
#define F3          0x3D00	/* Function key 3 scan code */
#define F4          0x3E00	/* Function key 4 scan code */
#define F5          0x3F00	/* Function key 5 scan code */
#define F6          0x4000	/* Function key 6 scan code */
#define F7          0x4100	/* Function key 7 scan code */
#define F8          0x4200	/* Function key 8 scan code */
#define F9          0x4300	/* Function key 9 scan code */
#define F10         0x4400	/* Function key 10 scan code */
#define F11         0x8500	/* Function key 11 scan code */
#define F12         0x8600	/* Function key 12 scan code */
#define UPG         0x48E0	/* Gray Up Arrow scan code */
#define UPW         0x4800	/* White Up Arrow scan code */
#define DOWNG       0x50E0	/* Gray Down Arrow scan code */
#define DOWNW       0x5000	/* White Down Arrow scan code */
#define LEFTG       0x4BE0	/* Gray Left Arrow scan code */
#define LEFTW       0x4B00	/* White Left Arrow scan code */
#define RIGHTG      0x4DE0	/* Gray Right Arrow scan code */
#define RIGHTW      0x4D00	/* White Right Arrow scan code */
#define K7          0x4737	/* Keyboard Numeric 7 scan code */
#define K8          0x4838	/* Keyboard Numeric 8 scan code */
#define K9          0x4939	/* Keyboard Numeric 9 scan code */
#define KDASH       0x372A	/* Keyboard Numeric Asterisk scan code */
#define K4          0x4B34	/* Keyboard Numeric 4 scan code */
#define K5          0x4C35	/* Keyboard Numeric 5 scan code */
#define K6          0x4D36	/* Keyboard Numeric 6 scan code */
#define KMINUS      0x4A2D	/* Keyboard Numeric Dash(minus) scan code */
#define K1          0x4F31	/* Keyboard Numeric 1 scan code */
#define K2          0x5032	/* Keyboard Numeric 2 scan code */
#define K3          0x5133	/* Keyboard Numeric 3 scan code */
#define KPLUS       0x4E2B	/* Keyboard Numeric + (plus) scan code */
#define K0          0x5230	/* Keyboard Numeric 0 scan code */
#define KDOT        0x532E	/* Keyboard Numeric Period scan code */
#define INSERTG	    0x52E0	/* Gray insert */
#define INSERTW	    0x5200	/* White insert */
#define DELETEG	    0x53E0	/* Gray delete */
#define DELETEW	    0x5300	/* White delete */
#define HOMEG	    0x47E0	/* Gray home */
#define HOMEW	    0x4700	/* White home */
#define ENDG	    0x4FE0	/* Gray end */
#define ENDW	    0x4F00	/* White end */
#define PGUPG	    0x49E0	/* Gray page up */
#define PGUPW	    0x4900	/* White page up */
#define PGDOWNG	    0x51E0	/* Gray page down */
#define PGDOWNW	    0x5100	/* White page down */
#define ALTX	    0x2D00	/* ALT-X: terminate session */
#define ALTE	    0x1200	/* ALT-E: DOS shell */

/*****************************************************************************/
/*external function prototypes                                               */

extern SendFuncPtr SendPacket;

/*****************************************************************************/
/* Local Static data                                                         */

static char cursorkey = '[';		/* Sequence character in cursor key */
static unsigned char applkeypad = 0;	/* Current state of keypad */

/*****************************************************************************/
/*****************************************************************************/


/*
 * Send a character
 */
static void ttoc(char c)
{
	SendPacket(&c, 1);
}


/*
 * Send two characters after an ESC
 */
static void ttoe2c(char c1, char c2)
{
char buff[3];

	buff[0] = ESC;
	buff[1] = c1;
	buff[2] = c2;
	SendPacket(buff, 3);
}


/*
 * Send two characters after ANSI
 */
static void ttoea2c(char c1, char c2)
{
char buff[4];

	buff[0] = ESC;
	buff[1] = 0x5b;
	buff[2] = c1;
	buff[3] = c2;
	SendPacket(buff, 4);
}


/*
 * Send three characters after ANSI
 */
static void ttoea3c(char c1, char c2, char c3)
{
char buff[5];

	buff[0] = ESC;
	buff[1] = 0x5b;
	buff[2] = c1;
	buff[3] = c2;
	buff[4] = c3;
	SendPacket(buff, 5);
}


/*  G E T K E Y  --  Return a keyboard scan code */

static unsigned int GetKey(void)
{
	return(_bios_keybrd(_NKEYBRD_READ)); /* check for waiting keystrokes */
}


/* T R A N S N U M K E Y  --  Try and translate key from the Numeric Keypad */

static int TransNumKey(register unsigned key)
{

	if (applkeypad != 0)	/* If keypad is not in NUMERIC mode */
		return (0);	/* then no translation here possible */

	switch (key) {
	case K7:		/* Numeric 7 pressed */
		ttoc('7');
		break;
	case K8:		/* Numeric 8 pressed */
		ttoc('8');
		break;
	case K9:		/* Numeric 9 pressed */
		ttoc('9');
		break;
	case KDASH:		/* Numeric Asterisk pressed */
		ttoc('*');
		break;
	case K4:		/* Numeric 4 pressed */
		ttoc('4');
		break;
	case K5:		/* Numeric 5 pressed */
		ttoc('5');
		break;
	case K6:		/* Numeric 6 pressed */
		ttoc('6');
		break;
	case KMINUS:		/* Numeric Minus pressed */
		ttoc('-');
		break;
	case K1:		/* Numeric 1 pressed */
		ttoc('1');
		break;
	case K2:		/* Numeric 2 pressed */
		ttoc('2');
		break;
	case K3:		/* Numeric 3 pressed */
		ttoc('3');
		break;
	case K0:		/* Numeric 0 pressed */
		ttoc('0');
		break;
	case KDOT:		/* Numeric Period pressed */
		ttoc('.');
		break;
	case KPLUS:		/* Numeric Plus pressed */
		ttoc('+');
		break;
	default:
		return (0);	/* No translation */
	}
	return (1);
}


/* T R A N S A P P L K E Y  --  Try and translate key from Application Keypad*/

static int TransApplKey(register unsigned key)
{

	if (applkeypad != 1)	/* If keypad is not APPLICATION mode */
		return (0);	/* then no translation here possible */

	switch (key) {
	case K0:		/* Application key 0 pressed */
		ttoe2c('O', 'p');
		break;
	case K1:		/* Application key 1 pressed */
		ttoe2c('O', 'q');
		break;
	case K2:		/* Application key 2 pressed */
		ttoe2c('O', 'r');
		break;
	case K3:		/* Application key 3 pressed */
		ttoe2c('O', 's');
		break;
	case K4:		/* Application key 4 pressed */
		ttoe2c('O', 't');
		break;
	case K5:		/* Application key 5 pressed */
		ttoe2c('O', 'u');
		break;
	case K6:		/* Application key 6 pressed */
		ttoe2c('O', 'v');
		break;
	case K7:		/* Application key 7 pressed */
		ttoe2c('O', 'w');
		break;
	case K8:		/* Application key 8 pressed */
		ttoe2c('O', 'x');
		break;
	case K9:		/* Application key 9 pressed */
		ttoe2c('O', 'y');
		break;
	case KDASH:		/* Application key Asterisk pressed */
		ttoe2c('O', 'm');
		break;
	case KMINUS:		/* Application key Minus pressed */
		ttoe2c('O', 'l');
		break;
	case KDOT:		/* Application key Dot pressed */
		ttoe2c('O', 'n');
		break;
	case KPLUS:		/* Application key Plus pressed */
		ttoe2c('O', 'M');
		break;
	default:
		return (0);	/* No translation */
	}
	return (1);
}


/* T R A N S K E Y  -- translate a scancode into a keystroke sequence */

static void TransKey(unsigned key)
{
char *value;
char n;

	n = _bios_keybrd(_KEYBRD_SHIFTSTATUS) & 3; /* shift state */
	if(n){          /* examine scrollback keys first */
           if(key == PGUPG || key == PGUPW){
	      SbkBack();
              return;
           } else if(key == PGDOWNG || key == PGDOWNW){
	      SbkForward();
              return;
           }
        }

        SbkSetPage(-1);

	if ((value = keymap_value(key)) != NULL) {
		SendPacket(value, strlen(value));
		return;
	}
	switch (key) {		/* Evaluate this keyboard scan code */

	case BKSP:		/* Backspace pressed */
		ttoc(DEL);
		break;

	case F1:		/* Function key 1 pressed */
		ttoea3c('1','1',0x7e);
		break;

	case F2:		/* Function key 2 pressed */
		ttoea3c('1','2',0x7e);
		break;

	case F3:		/* Function key 3 pressed */
		ttoea3c('1','3',0x7e);
		break;

	case F4:		/* Function key 4 pressed */
		ttoea3c('1','4',0x7e);
		break;

	case F5:		/* Function key 5 pressed */
		ttoea3c('1','5',0x7e);
		break;

	case F6:		/* Function key 6 pressed */
		ttoea3c('1','7',0x7e);
		break;

	case F7:		/* Function key 7 pressed */
		ttoea3c('1','8',0x7e);
		break;

	case F8:		/* Function key 8 pressed */
		ttoea3c('1','9',0x7e);
		break;

	case F9:		/* Function key 9 pressed */
		ttoea3c('2','0',0x7e);
		break;

	case F10:		/* Function key 10 pressed */
		ttoea3c('2','1',0x7e);
		break;

	case F11:		/* Function key 11 pressed */
		ttoea3c('2','3',0x7e);
		break;

	case F12:		/* Function key 12 pressed */
		ttoea3c('2','4',0x7e);
		break;

	case UPG:		/* Up Arrow pressed */
	case UPW:
		ttoe2c(cursorkey, 'A');
		break;

	case DOWNG:		/* Down Arrow pressed */
	case DOWNW:
		ttoe2c(cursorkey, 'B');
		break;

	case RIGHTG:		/* Right Arrow pressed */
	case RIGHTW:
		ttoe2c(cursorkey, 'C');
		break;

	case LEFTG:		/* Left Arrow pressed */
	case LEFTW:
		ttoe2c(cursorkey, 'D');
		break;

        case INSERTG:
	case INSERTW:
                ttoea2c('2', 0x7E);
                break;

        case DELETEG:
	case DELETEW:
		ttoea2c('3', 0x7E);
                break;

        case HOMEG:
	case HOMEW:
                ttoe2c('O', 'H');
                break;

        case ENDG:
	case ENDW:
                ttoe2c('O', 'F');
                break;

        case PGUPG:
	case PGUPW:
                ttoea2c('5', 0x7E);
                break;

        case PGDOWNG:
	case PGDOWNW:
                ttoea2c('6', 0x7E);
                break;

	case ALTX:
		fatal("Terminating session");

	case ALTE: /* DOS shell */
                Shell();
		break;

	default:		/* No translation yet, check numeric pad */
		if ((TransNumKey(key) == 0) && (TransApplKey(key) == 0))
			ttoc((char) key);	/* Still no translation, transmit char */
		break;
	}
}


/*  C O N C H K  --  Check if any key strokes are waiting */

int ConChk(void)
{
	return(_bios_keybrd(_NKEYBRD_READY));
}


/*  D O K E Y  --  Retrieve and interpret a keystroke */

void DoKey(void)
{
unsigned scancode;

	scancode = GetKey();	/* Get a keystroke, waits if none ready */
	TransKey(scancode);
}


/* S E T K E Y P A D -- Set the keypad translation */

void SetKeyPad(int mode)
{
	applkeypad = mode ? 1 : 0;	/* keypad = APPLICATION/NUMERIC */
}

/* S E T C U R S O R K E Y -- Set the cursior key mode */

void SetCursorKey(mode)
{	
	/* This establishes the second character */
	/* of the cursor keys escape sequence */
	cursorkey = mode ? 'O' : '[';
}
