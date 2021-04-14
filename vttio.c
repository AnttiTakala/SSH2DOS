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
#include <dos.h>
#include <conio.h>
#include <string.h>

#include "config.h"
#include "channel.h"
#include "vidio.h"
#include "keyio.h"

#define BLINK         0x80	/* Blink video attribute */
#define NORMAL        0x7	/* Normal video attribute */
#define BOLD          0x8	/* Bold video attribute */
#define UNDERLINED    0xA	/* Underlined video attribute */
#define REVERSE       0x70	/* Reverse video attribute */
#define TRUE	      1
#define FALSE	      0

/****************************************************************************/
/* Global variables                                                         */

unsigned originmode;		/* Origin mode, relative or absolute */
unsigned insertmode;		/* Insert mode, off or on */
unsigned autowrap;		/* Automatic wrap mode, off or on */
unsigned newline=0;		/* Newline mode, off or on,  GLOBAL data! */
unsigned cursorvisible;		/* Cursor visibility, on or hidden */
unsigned reversebackground;	/* Reverse background attribute, on or off */
unsigned screenwid;		/* Screen column width */
unsigned char log;		/* Flag to indicate char logging is on */
unsigned PrintInAction;		/* Flag to indicate local printing is on */

/****************************************************************************/
/* External variables                                                       */

extern unsigned columns;	/* Columns on logical terminal screen */
extern unsigned lines;		/* Lines on logical terminal screen */
extern unsigned char curattr;
extern int cursx;
extern int cursy;
extern unsigned char scrolltop;
extern unsigned short statusline;

/*external function prototypes                                               */
extern SendFuncPtr SendPacket;

/*
 * Static functions
 */
static void atnrm(unsigned char);
static void atescf(unsigned char);
static void AnsiParse(unsigned char);
static void ExtParse(unsigned char);
static void AnsiModeSet(char, int);
static void ExtModeSet(char, int);
static void LinuxParse(unsigned char);
static void ColorParse(unsigned char);
static void SetChar0(unsigned char);
static void SetChar1(unsigned char);
static void SetDouble(unsigned char);
static void TransmitId(void);
static void VTBell(void);
static void (*ttstate) (unsigned char) = atnrm;

/****************************************************************************/
/* Local static data                                                        */

static char term_id_str[] = "[?1;2c";	/* VT100 id string */
#define lansarg 10		/* Max number of ANSI arguments */
static int nansarg = 0;		/* Index for ANSI argument list */
static int ansargs[lansarg];	/* Room for 10 ANSI arguments */
static unsigned char lastc;	/* Saved last character */
static int nclrarg = 0;		/* Index for color definition argument */
static unsigned char clrargs[4];	/* Room for 4 arguments nrgb */

/*****************************************************************************/
/*****************************************************************************/

/*#define	ISO8859_MAP*/

static unsigned char outputtable[256] = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
	0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
	0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
	0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
	0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
	0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
	0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
	0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
	0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
	0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
	0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
	0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
	0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
	0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
	0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
	0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
	0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
	0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
#ifndef	ISO8859_MAP
	0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
	0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
	0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
	0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
	0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
	0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
	0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
	0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
	0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
	0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
	0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
	0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
#else
	0xFE,			/* 0xA0, NO-BREAK SPACE */
	0xAD,			/* 0xA1, INVERTED EXCLAMATION */
	0x9B,			/* 0xA2, CENT SIGN */
	0x9C,			/* 0xA3, POUND SIGN */
	0xFE,			/* 0xA4, CURRENCY SIGN */
	0x9D,			/* 0xA5, YEN SIGN */
	0xFE,			/* 0xA6, BROKEN BAR */
	0x15,			/* 0xA7, PARAGRAPH SIGN, SECTION SIGN */
	0xFE,			/* 0xA8, DIARESIS */
	0xFE,			/* 0xA9, COPYRIGHT SIGN */
	0xA6,			/* 0xAA, FEMININE ORDINAL INDICATOR */
	0xAE,			/* 0xAB, LEFT ANGLE QUOTATION MARK */
	0xAA,			/* 0xAC, NOT SIGN */
	0xFE,			/* 0xAD, SOFT HYPHEN */
	0xFE,			/* 0xAE, REGISTERED TRADE MARK SIGN */
	0x16,			/* 0xAF, MACRON */
	0xF8,			/* 0xB0, RING ABOVE, DEGREE SIGN */
	0xF1,			/* 0xB1, PLUS-MINUS SIGN */
	0xFD,			/* 0xB2, SUPERSCRIPT TWO */
	0xFE,			/* 0xB3, SUPERSCRIPT THREE */
	0xFE,			/* 0xB4, ACUTE ACCENT */
	0xE6,			/* 0xB5, MICRO SIGN */
	0x14,			/* 0xB6, PILCROW SIGN */
	0xFA,			/* 0xB7, MIDDLE DOT */
	0xFE,			/* 0xB8, CEDILLA */
	0xFE,			/* 0xB9, SUPERSCRIPT ONE */
	0xA7,			/* 0xBA, MASCULINE ORDINAL INDICATOR */
	0xAF,			/* 0xBB, RIGHT ANGLE QUOTATION MARK */
	0xAC,			/* 0xBC, VULGAR FRACTION ONE QUARTER */
	0xAB,			/* 0xBD, VULGAR FRACTION ONE HALF */
	0xFE,			/* 0xBE, VULGAR FRACTION THREE QUARTERS */
	0xA8,			/* 0xBF, INVERTED QUESTION MARK */
	0xFE,			/* 0xC0, CAPITAL LETTER A WITH GRAVE ACCENT */
	0xFE,			/* 0xC1, CAPITAL LETTER A WITH ACUTE ACCENT */
	0xFE,			/* 0xC2, CAPITAL LETTER A WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xC3, CAPTIAL LETTER A WITH TILDE */
	0x8E,			/* 0xC4, CAPITAL LETTER A WITH DIAERSIS */
	0x8F,			/* 0xC5, CAPITAL LETTER A WITH RING ABOVE */
	0x92,			/* 0xC6, CAPITAL DIPHTHONG A WITH E */
	0x80,			/* 0xC7, CAPTIAL LETTER C WITH CEDILLA */
	0xFE,			/* 0xC8, CAPITAL LETTER E WITH GRAVE ACCENT */
	0x90,			/* 0xC9, CAPITAL LETTER E WITH ACUTE ACCENT */
	0xFE,			/* 0xCA, CAPITAL LETTER E WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xCB, CAPITAL LETTER E WITH DIAERSIS */
	0xFE,			/* 0xCC, CAPITAL LETTER I WITH GRAVE ACCENT */
	0xFE,			/* 0xCD, CAPITAL LETTER I WITH ACUTE ACCENT */
	0xFE,			/* 0xCE, CAPITAL LETTER I WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xCF, CAPITAL LETTER I WITH DIAERSIS */
	0xFE,			/* 0xD0, CAPITAL ICELANDIC LETTER ETH */
	0xA5,			/* 0xD1, CAPITAL LETTER N WITH TILDE */
	0xFE,			/* 0xD2, CAPITAL LETTER O WITH GRAVE ACCENT */
	0xFE,			/* 0xD3, CAPITAL LETTER O WITH ACUTE ACCENT */
	0xFE,			/* 0xD4, CAPITAL LETTER O WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xD5, CAPITAL LETTER O WITH TILDE */
	0x99,			/* 0xD6, CAPITAL LETTER O WITH DIAERSIS */
	0xFE,			/* 0xD7, MULTIPLICATION SIGN */
	0xFE,			/* 0xD8, CAPITAL LETTER O WITH OBLIQUE STROKE */
	0xFE,			/* 0xD9, CAPITAL LETTER U WITH GRAVE ACCENT */
	0xFE,			/* 0xDA, CAPITAL LETTER U WITH ACUTE ACCENT */
	0xFE,			/* 0xDB, CAPITAL LETTER U WITH CIRCUMFLEX ACCENT */
	0x9A,			/* 0xDC, CAPITAL LETTER U WITH DIAERSIS */
	0xFE,			/* 0xDD, CAPITAL LETTER Y WITH ACUTE ACCENT */
	0xFE,			/* 0xDE, CAPITAL ICELANDIC LETTER THORN */
	0xE1,			/* 0xDF, SMALL GERMAN LETTER SHARP s */
	0x85,			/* 0xE0, SMALL LETTER a WITH GRAVE ACCENT */
	0xA0,			/* 0xE1, SMALL LETTER a WITH ACUTE ACCENT */
	0x83,			/* 0xE2, SMALL LETTER a WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xE3, SMALL LETTER a WITH TILDE */
	0x84,			/* 0xE4, SMALL LETTER a WITH DIAERSIS */
	0x86,			/* 0xE5, SMALL LETTER a WITH RING ABOVE */
	0x91,			/* 0xE6, SMALL DIPHTHONG a WITH e */
	0x87,			/* 0xE7, SMALL LETTER c WITH CEDILLA */
	0x8A,			/* 0xE8, SMALL LETTER e WITH GRAVE ACCENT */
	0x82,			/* 0xE9, SMALL LETTER e WITH ACUTE ACCENT */
	0x88,			/* 0xEA, SMALL LETTER e WITH CIRCUMFLEX ACCENT */
	0x89,			/* 0xEB, SMALL LETTER e WITH DIAERSIS */
	0x8D,			/* 0xEC, SMALL LETTER i WITH GRAVE ACCENT */
	0xA1,			/* 0xED, SMALL LETTER i WITH ACUTE ACCENT */
	0x8C,			/* 0xEE, SMALL LETTER i WITH CIRCUMFLEX ACCENT */
	0x8B,			/* 0xEF, SMALL LETTER i WITH DIAERSIS */
	0xFE,			/* 0xF0, SMALL ICELANDIC LETTER ETH */
	0xA4,			/* 0xF1, SMALL LETTER n WITH TILDE */
	0x95,			/* 0xF2, SMALL LETTER o WITH GRAVE ACCENT */
	0xA2,			/* 0xF3, SMALL LETTER o WITH ACUTE ACCENT */
	0x93,			/* 0xF4, SMALL LETTER o WITH CIRCUMFLEX ACCENT */
	0xFE,			/* 0xF5, SMALL LETTER o WITH TILDE */
	0x94,			/* 0xF6, SMALL LETTER o WITH DIAERSIS */
	0xF6,			/* 0xF7, DIVISION SIGN */
	0xED,			/* 0xF8, SMALL LETTER o WITH OBLIQUE STROKE */
	0x97,			/* 0xF9, SMALL LETTER u WITH GRAVE ACCENT */
	0xA3,			/* 0xFA, SMALL LETTER u WITH ACUTE ACCENT */
	0x96,			/* 0xFB, SMALL LETTER u WITH CIRCUMFLEX ACCENT */
	0x81,			/* 0xFC, SMALL LETTER u WITH DIAERSIS */
	0xFE,			/* 0xFD, SMALL LETTER y WITH ACUTE ACCENT */
	0xFE,			/* 0xFE, SMALL ICELANDIC LETTER THORN */
	0x98			/* 0xFF, SMALL LETTER y WITH DIAERSIS */
#endif
};


/*  V T I N I T  --   */

void VTInit(void)
{
	screenwid = columns;
	autowrap = 1;
	insertmode = 0;
	cursorvisible = 1;
	reversebackground = 0;
	log = 0;
	PrintInAction = 0;

	SetVattr(NORMAL);
	ttstate = atnrm;	/* initial output state is normal */
	SetScroll(0, 0);
	ClearScreen();
	SetCharSet(0, 'B');
	SetCharSet(1, 'B');
	MapCharSet(0);
	ClearAllTabs();
	InitTabs();
	SetScreenWidth(screenwid);
	SetCursorVisibility(cursorvisible);
	SetBackGround(reversebackground);
	SetCurs(1, 1);
	SaveCursor();
	lastc = '\0';
}


/*  C O N O U T  --  Put a character to the terminal screen */

void ConOut(unsigned char c)
{
	(*ttstate) (c);
	lastc = c;
}


/*  A T N R M  --  local routine to process an arbitrary character */

static void atnrm(unsigned char c)
{
	switch (c) {
	   case 0:
		break;

	   case 7:	/* Ring terminal bell */
		VTBell();
		break;

	   case 8:	/* back space */
		SetRelCurs(-1, 0);
		break;
                          
	   case 9:	/* Horizontal tab */
		if(PrintInAction)
		   fputc('\t',stdprn);
		else
		   DoTab();
		break;

	   case 10:	/* Line feed */
	   case 11:
	   case 12:
		if(cursy == lines - statusline) /* we are at the bottom */
		   SbkAddline();
		if(PrintInAction)
		   fputc('\n',stdprn);
		else if (newline){
			SetCurs(1, 0);
			ScrollUp();
			}
		else ScrollUp();
		break;

	   case 13:	/* Carriage return */
		if(PrintInAction)
		   fputc('\r',stdprn);
		else
		   SetCurs(1, 0);
		break;

	   case 14:	/* Map G1 to current */
		MapCharSet(1);
		break;

	   case 15:	/* Map G0 to current */
		MapCharSet(0);
		break;

	   case 24:	/* Exit Control Sequence */
	   case 26:	/* Exit Control Sequence */
		ttstate = atnrm;
		break;

	   case 27:	/* Escape */
		ttstate = atescf;	/* next state parser is esc follower */
		break;

	   case 155:
		memset(ansargs, 0, sizeof(ansargs));
		nansarg = 0;
		ttstate = AnsiParse;
		break;

	   default:
		if(PrintInAction)
		   fputc(outputtable[c],stdprn);
		else
		   ChrWrite(outputtable[c]);
		break;
	}
}

/*  A T E S C F  --  escape follower */

static void atescf(c)
unsigned char c;
{
	switch (c) {

	   case '[':		/* Parse ansi args */
		memset(ansargs, 0, sizeof(ansargs));
		nansarg = 0;
		ttstate = AnsiParse;
		return;

	   case ']':
		memset(ansargs, 0, sizeof(ansargs));
		nansarg = 0;
		ttstate = LinuxParse;
		return;

	   case '(':		/* Select character set G0 */
		ttstate = SetChar0;
		return;

	   case ')':		/* Select character set G1 */
		ttstate = SetChar1;
		return;

	   case '#':		/* Set double high/wide characters */
		ttstate = SetDouble;
		return;

	   case '>':		/* Enable numeric keypad */
		SetKeyPad(0);
		break;

	   case '=':		/* Enable application keypad */
		SetKeyPad(1);
		break;

	   case '7':		/* Save cursor, attributes description */
		SaveCursor();
		break;

	   case '8':		/* Restore cursor, attributes description */
		RestoreCursor();
		break;

	   case 'D':		/* Cursor down, scroll up if at bottom */
		ScrollUp();
		break;

	   case 'E':		/* Carriage return/line feed combination */
		SetCurs(1, 0);
		ScrollUp();
		break;

	   case 'H':		/* Set a tab stop */
		SetTabStop();
		break;

	   case 'M':		/* Cursor up, scroll down if at top */
		ScrollDown();
		break;

	   case 'Z':		/* Transmit the terminal ID */
		TransmitId();
		break;

	   case 'c':		/* Reset terminal to power on values */
		VTInit();
		break;

	   default:
		break;
	}

   ttstate = atnrm;
}

/*  A N S I P A R S E  --  parse ansi arguments */

static void AnsiParse(c)
unsigned char c;
{
unsigned char savetop;
register int i;
register int j;

	c &= 0x7F;
	switch (c) {

	case 8:		/* backspace*/
		SetRelCurs(-1, 0);
		break;

	case '\r':	/* Carriage return */
		SetCurs(1, 0);
		break;

	case '\v':
		SetRelCurs(0, 1);
		break;

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		ansargs[nansarg] = (ansargs[nansarg] * 10) + (c - '0');
		break;

	case ';':		/* Argument separator */
		if (++nansarg > lansarg)
			ttstate = atnrm;
		break;

	case '?':		/* Extended mode set/reset */
		ttstate = (lastc == '[') ? ExtParse : atnrm;
		break;

	case '@':		/* scroll line to right from cursor */
		if (nansarg && ansargs[0] > 0)
		   ansargs[0] = 1; /* assume one char */
		for (i = 0; i < ansargs[0]; i++)
		   LineRight();
		ttstate = atnrm;
		break;

	case 'A':		/* Move cursor up */
		SetRelCurs(0, (ansargs[0] == 0) ? -1 : -ansargs[0]);
		ttstate = atnrm;
		break;

	case 'B':		/* Move cursor down */
	case 'e':
		SetRelCurs(0, (ansargs[0] == 0) ? 1 : ansargs[0]);
		ttstate = atnrm;
		break;

	case 'C':		/* Move cursor right */
	case 'a':
		SetRelCurs((ansargs[0] == 0) ? 1 : ansargs[0], 0);
		ttstate = atnrm;
		break;

	case 'D':		/* Move cursor left */
		SetRelCurs(ansargs[0] == 0 ? -1 : -ansargs[0], 0);
		ttstate = atnrm;
		break;

	case 'E':		/* Move cursor to first char and down */
		SetCurs(1, 0);
		SetRelCurs(0, (ansargs[0] == 0) ? 1 : ansargs[0]);
		ttstate = atnrm;
		break;

	case 'F':		/* Move cursor to first char and up */
		SetCurs(1, 0);
		SetRelCurs(0, (ansargs[0] == 0) ? -1 : -ansargs[0]);
		ttstate = atnrm;
		break;

	case 'G':		/* set horizontal position */
	case '`':
		i = ansargs[0];
		if (i == 0)
			i = 1;
		SetCurs(i, 0);
		ttstate = atnrm;
		break;

	case 'H':		/* Address cursor to line and column */
	case 'f':
		i = ansargs[0];
		j = ansargs[1];
		if (i == 0)
			i = 1;
		if (j == 0)
			j = 1;
		SetCurs(j, i);

		ttstate = atnrm;
		break;

	case 'J':		/* Erase screen */
		if (ansargs[0] == 0) {	/* from cursor to end of the screen */
			ClearEOS();
		} else if (ansargs[0] == 1) {	/* from home position to cursor */
			ClearBOS();
		} else if (ansargs[0] == 2) {	/* whole screen */
			ClearScreen();
		}
		ttstate = atnrm;
		break;

	case 'K':		/* Erase Line */
		if (ansargs[0] == 0)	/* from cursor to end of the line */
			ClearEOL();
		else if (ansargs[0] == 1)	/* start of line to cursor */
			ClearBOL();
		else if (ansargs[0] == 2) {	/* whole line */
			ClearBOL();
			ClearEOL();
		}
		ttstate = atnrm;
		break;

	case 'L':		/* Insert line */
		savetop = scrolltop;
		scrolltop = cursy; /* Don't use SetScroll as it homes the cursor */
		if (nansarg && ansargs[0] > 0)
		   ansargs[0] = 1; /* assume one char */
		for (i = 0; i < ansargs[0]; i++)
		   IndexDown();
		scrolltop = savetop;
		ttstate = atnrm;
		break;

	case 'M':		/* delete line */
		savetop = scrolltop;
		scrolltop = cursy; /* Don't use SetScroll as it homes the cursor */
		if (nansarg && ansargs[0] > 0)
		   ansargs[0] = 1; /* assume one char */
		for (i = 0; i < ansargs[0]; i++)
 		   IndexUp();
		scrolltop = savetop;
		ttstate = atnrm;
		break;

	case 'P':		/* Delete characters */
		if (nansarg && ansargs[0] > 0)
                   ansargs[0] = 1; /* assume one char */
        	for (i = 0; i < ansargs[0]; i++)
                   ChrDelete();
		ttstate = atnrm;
		break;

	case 'X': /* Erase characters */
		ClearBox(cursx, cursy, cursx + ansargs[0], cursy, curattr);
		ttstate = atnrm;
		break;

	case 'c':		/* Transmit the terminal ID */
		TransmitId();
		break;

	case 'd':		/* set vertical position */
		i = ansargs[0];
		if (i == 0)
			i = 1;
		SetCurs(0, i);
		ttstate = atnrm;
		break;

	case 'g':		/* Tab stop set/reset */
		if (ansargs[0] == 0)
			ClearTabStop();
		else if (ansargs[0] == 3)
			ClearAllTabs();
		ttstate = atnrm;
		break;

	case 'h':		/* Set ANSI mode */
		for (i = 0, ++nansarg; i < nansarg && i <= lansarg; i++)
			AnsiModeSet(ansargs[i], 1);
		ttstate = atnrm;
		break;

	case 'i':		/* Local printing */
		if ((ansargs[0] == 5) && PrintInAction==FALSE ) /* start local printing */
			PrintInAction=TRUE;
		else if ((ansargs[0] == 4) && PrintInAction==TRUE) /* Stop local printing */
			PrintInAction=FALSE;
		ttstate = atnrm;
		break;

	case 'l':		/* Reset ANSI mode */
		for (i = 0, ++nansarg; i < nansarg && i <= lansarg; i++)
			AnsiModeSet(ansargs[i], 0);
		ttstate = atnrm;
		break;

	case 'm':		/* Select screen attribute */
		ttstate = atnrm;
		if (++nansarg <= lansarg) {
			for (i = 0; i < nansarg; i++) {
				switch (ansargs[i]) {
				case 0: /* Turn off all attributes */
					i == 0 ? SetVattr(NORMAL) : AddVattr(NORMAL);
					break;
				case 1:
					i == 0 ?  SetVattr(BOLD) : AddVattr(BOLD);
					break;
				case 2:
					SubVattr(BOLD);
					break;
				case 4: /* Begin underline mode */
					i == 0 ? SetVattr(UNDERLINED) : AddVattr(UNDERLINED);
					break;
				case 5:
					i == 0 ? SetVattr(BLINK) : AddVattr(BLINK);
					break;
				case 7: /* Begin standout mode */
					i == 0 ? SetVattr(REVERSE) : AddVattr(REVERSE);
					break;

				case 8: /* Turn on blank mode - characters invisible */
                                        curattr &= 0xF0;
                                        curattr |= curattr >> 4;
                                        break;

/*				case 10:*/ /* Exit PC character mode */
/*				case 11:*/ /* Enter PC character display mode */

				case 21:
				case 22:
					SubVattr(BOLD);
					break;
				case 24:
					SubVattr(UNDERLINED);
					break;
				case 25:
					SubVattr(BLINK);
					break;
				case 27:
					SubVattr(REVERSE);
					break;

#if defined (COLOR)
				case 30: /* BLACK */
					curattr &= 0xF8 ;
					break;
				case 31: /* RED */
					curattr &= 0xF8 ;
					curattr |= 4 ;
					break;
				case 32: /* GREEN */
					curattr &= 0xF8 ;
					curattr |= 2 ;
					break;
				case 33: /* YELLOW */
					curattr &= 0xF8 ;
					curattr |= 6 ;
					break;
				case 34: /* BLUE */
					curattr &= 0xF8 ;
					curattr |= 1 ;
					break;
				case 35: /* MAGENTA */
					curattr &= 0xF8 ;
					curattr |= 5 ;
					break;
				case 36: /* CYAN */
					curattr &= 0xF8 ;
					curattr |= 3 ;
					break;
				case 37: /* WHITE */
					curattr &= 0xF8 ;
					curattr |= 7 ;
					break;
				case 39:
				case 49: /* Set default pair to its original value */
					SetVattr(NORMAL);
					break;
				case 40: /* BLACK */
					curattr &= 0x8F ;
					break;
				case 41: /* RED */
					curattr &= 0x8F ;
					curattr |= 0x40 ;
					break;
				case 42: /* GREEN */
					curattr &= 0x8F ;
					curattr |= 0x20 ;
					break;
				case 43: /* YELLOW */
					curattr &= 0x8F ;
					curattr |= 0x60 ;
					break;
				case 44: /* BLUE */
					curattr &= 0x8F ;
					curattr |= 0x10 ;
					break;
				case 45: /* MAGENTA */
					curattr &= 0x8F ;
					curattr |= 0x50 ;
					break;
				case 46: /* CYAN */
					curattr &= 0x8F ;
					curattr |= 0x30 ;
					break;
				case 47: /* WHITE */
					curattr &= 0x8F ;
					curattr |= 0x70 ;
					break;

#endif /* color */

				default:
					break;
				}
			}
		}
		break;

	case 'r':		/* Define scrolling region */
		SetScroll(ansargs[0], ansargs[1]);
		ttstate = atnrm;
		break;

	case 's':		/* Save cursor */
		SaveCursor();
		ttstate = atnrm;
		break;

	case 'u':		/* Restore cursor */
		RestoreCursor();
		ttstate = atnrm;
		break;

	default:		/* unrecognized so ignore */
		ttstate = atnrm;
		break;
	}
}

/* E X T P A R S E  -- Parse extended mode Set/Reset */

static void ExtParse(unsigned char c)
{
	register int i;

	switch (c) {

	case '0':
	case '1':
	case '2':
	case '3':
	case '4':
	case '5':
	case '6':
	case '7':
	case '8':
	case '9':
		ansargs[nansarg] = (ansargs[nansarg] * 10) + (c - '0');
		return;

	case ';':		/* Argument separator */
		if (++nansarg > lansarg)
			ttstate = atnrm;
		return;

	case 'c': /* FIXME: Cursor: 1 - visible, 0 - normal, 8 - very visible */
		ttstate = atnrm;
		return;

	case 'h':
		for (i = 0, ++nansarg; i < nansarg && i <= lansarg; i++)
			ExtModeSet(ansargs[i], 1);
		ttstate = atnrm;
		return;

	case 'l':
		for (i = 0, ++nansarg; i < nansarg && i <= lansarg; i++)
			ExtModeSet(ansargs[i], 0);
		ttstate = atnrm;
		return;

        case 's':  /* FIXME */
		ttstate = atnrm;
                break;

	default:
		ttstate = atnrm;
		return;
	}
}

/* L I N U X P A R S E  -- Set/Reset color palette,  ESC ] { Pnrrggbb | R } */

static void LinuxParse(c)
unsigned char c;
{
	c &= 0x7F;
        switch(c){
           case 7: /* set window title end - unsupported */
	        ttstate = atnrm;
                break;

	   case 'P':
	        memset(clrargs, 0, sizeof(clrargs));
        	nclrarg = 0;
        	ttstate = ColorParse;
                break;

           case 'R':
	        ResetColorPalette();
	        ttstate = atnrm;
                break;

           default:
		break;
     }
}


/* E X T M O D E S E T  --  Set/Reset extended mode after ESC [ ? */

static void ExtModeSet(char c, int mode)
{

	switch (c) {
	case 1:		/* Cursor Key Mode (DECCKM) */
		SetCursorKey(mode);
		break;

	case 2:		/* FIXME: ANSI/VT52 Mode (DECANM) */
		break;

	case 3:		/* Column Mode (DECCOLM) */
		SetScreenWidth(mode ? 132 : 80);
		break;

	case 4:		/* FIXME: Scrolling Mode (DECSCLM) */
		break;

	case 5:		/* Screen Mode (DECSCNM) */
		SetBackGround(mode);
		break;

	case 6:		/* Origin Mode (DECOM) */
		originmode = mode;
		break;

	case 7:		/* Auto Wrap Mode (DECAWM) */
		autowrap = mode;
		break;

	case 8:		/* FIXME: Auto repeat on/off DECARM */
		break;

	case 18:	/* FIXME: Print Form Feed Mode (DECPFF) */
		break;

	case 19:	/* FIXME: Print Extent Mode (DECPEX) */
		break;

	case 25:	/* Text cursor enable (DECTCEM) */
		SetCursorVisibility(mode);
		break;

	case 42:	/* FIXME: Character Set Mode (DECNRCM) */
		break;

	default:
		break;
	}
}


/* C O L O R P A R S E  -- Set/Reset color palette,  ESC ] { Pnrrggbb | R } */

static void ColorParse(c)
unsigned char c;
{
	int n = -1, i;

	if (c >= '0' && c <= '9')
		n = c - '0';
	else if (c >= 'A' && c <= 'F')
		n = c - 'A' + 10;
	else if (c >= 'a' && c <= 'f')
		n = c - 'a' + 10;

	if ( n >= 0 ) {
		i = (++nclrarg) >> 1;
		clrargs[i] = clrargs[i] * 16 + n;
		if ( nclrarg == 7 ) {
			n = clrargs[0];
			switch ( n ) {
			case 0x01:
			case 0x03:
			case 0x09:
			case 0x0B:
				n += 3;
				break;

			case 0x04:
			case 0x06:
			case 0x0C:
			case 0x0E:
				n -= 3;
				break;

			default:
				break;
			}
			SetColorPalette(n, clrargs + 1);
			ttstate = atnrm;
		}
	} else
		ttstate = atnrm;
}


/* A N S I M O D E S E T  -- Set/Reset ANSI mode   ,  ESC [ P1,,, Pn h/l */

static void AnsiModeSet(char c, register int mode)
{

	switch (c) {
	case 2:		/* Lock/unlock keyboard */
		break;

	case 4:		/* Insert/Replace setting */
		insertmode = mode;
		break;

	case 12:		/* FIXME Echo on/off */
		break;

	case 20:		/* New Line mode */
		newline = mode;
		break;

	default:
		break;
	}
}


/* A T C H R S E T 0 -- Set the current character set for G0 */

static void SetChar0(unsigned char c)
{
	SetCharSet(0, c);
	ttstate = atnrm;
}


/* A T C H R S E T 1 -- Set the current character set for G1 */

static void SetChar1(unsigned char c)
{
	SetCharSet(1, c);
	ttstate = atnrm;
}


/* S E T D O U B L E -- Set the current line to double high and/or wide */

static void SetDouble(unsigned char c)
{

	switch (c) {
	case '5':		/* Single width */
	case '6':		/* Double width */
	case '3':		/* Double height/width */
	case '4':		/* Bottom half of double height/width */
	default:
		;
	}
	ttstate = atnrm;

}


/* T R A N S M I T I D -- Transmit the terminal id to the host */

static void TransmitId(void)
{
char c = 27;
	SendPacket(&c, 1);
	SendPacket(term_id_str, strlen(term_id_str));
}


/*  V T B E L L  --  Do a VT100 style bell */

static void VTBell(void)
{
	sound(880);
	delay(125);
	nosound();
}

