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
 * Modified by Nagy Daniel - OpenWatcom
 *			   - added ChrDelete function
 *			   - added LineRight function
 *			   - removed unnecessary things (sorry, need memory)
 *                         - added scrollback support
 */

#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <string.h>
#include <stdarg.h>
#include <dos.h>
#include <i86.h>

#include "config.h"
#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

#define SCROLLBUFSIZE	32768 /* size of scrollback buffer (short)*/

#if defined (__386__)
 #undef MK_FP
 static char *MK_FP (unsigned short seg, unsigned short ofs)
 {
      return (char *) ((seg << 4) + ofs);
 }
#endif

 static char peekb(unsigned short segment, unsigned short offset)
 {
 char *p;
   p = MK_FP(segment, offset);
   return(*p);
 }
 static short peekw(unsigned segment, unsigned offset)
 {
 short *p;
   p = (short *)MK_FP(segment, offset);
   return(*p);
 }

#define BLINK         0x80	/* Blink video attribute */
#define NORMAL        0x7	/* Normal video attribute */
#define BOLD          0x8	/* Bold video attribute */
#define UNDERLINED    0xA	/* Underlined video attribute */
#define REVERSE       0x70	/* Reverse video attribute */
#define SCREEN        0x10	/* BIOS video interrupt number */
#define RETRACE       0x3da	/* Video Retrace port address for CGA */
#define ASCII         0		/* ASCII character set */
#define UK            1		/* UK character set */
#define SPECIAL       2		/* Special character set, graphics chars */

/****************************************************************************/
/* Global Data                                                              */

unsigned short statusline = 1;  /* status line */
unsigned short vidmode = 0;	/* Screen video mode */
unsigned short origvmode = 0;	/* Original video mode */
unsigned columns;		/* Columns on logical terminal screen */
unsigned lines;			/* Lines on logical terminal screen */
int cursx;		/* X cursor position */
int cursy;		/* Y cursor position */
unsigned char scrolltop;	/* Top row of scrolling region */
unsigned char curattr;	/* Video attribute of displayable chars */
char vidpages;		/* number of video pages in current mode */

/****************************************************************************/
/* External variables                                                       */

extern Config GlobalConfig;
extern unsigned short Configuration;

extern unsigned originmode;	/* Origin mode, relative or absolute */
extern unsigned insertmode;	/* Insert mode, off or on */
extern unsigned autowrap;	/* Automatic wrap mode, off or on */
extern unsigned cursorvisible;	/* Cursor visibility, on or hidden */
extern unsigned reversebackground;	/* Reverse background attribute, on or off */
extern unsigned screenwid;	/* Absolute screen width */


/***************************************************************************/
/* Local static data                                                       */

static unsigned char retracemode = 0;	/* Flag indicating No Video refresh wait */
static unsigned isvga = 0;		/* Is VGA */
static unsigned char screentop;	/* Absolute top of screen */
static unsigned char screenbot;	/* Absolute bottom of screen */
static unsigned char scrollbot;	/* Bottom row of scrolling region */
static unsigned char CharCounter; /* for Brailab adapter support */

static unsigned scroff;		/* Screen memory offset */
static unsigned scrseg;		/* Screen memory segment */
static char *screen;            /* Pointer to video screen */
static unsigned char video_state;	/* State of video, reversed or normal */
static unsigned char scbattr;	/* Video attribute of empty video cell */
static unsigned char baseattr;	/* Base attribute for video attributes */
static unsigned char extrattr;	/* Extra attribute for video attributes */
static unsigned char vesa;      /* is VESA available? */
static char actpage;   		/* actual video page */
static char *scrollbuf;		/* scrollback buffer */

static unsigned char att_reverse;	/* Reverse attribute bits */
static unsigned char att_normal;	/* Normal attribute bits */
static unsigned char att_low_mask = 0x6;	/* Low attribute mask */
static unsigned char att_underline = 0x1;	/* Underlined attribute bit */
static unsigned char att_intensity = 0x8;	/* Bold attribute bit */
static unsigned char att_blink = 0x80;	/* Blinking attribute bit */

static char tabs[132];		/* active tab stops */
static char deftabs[132];	/* default tab stops, 9,17,26 .... */

static int G0 = ASCII;		/* Character set G0 */
static int G1 = ASCII;		/* Character set G1 */
static int *GL = &G0;		/* Pointer to current mapped character set */

static char special_chars[32] = {	/* Special characters */
	32, 4, 176, 9, 12, 13, 10, 248, 241, 18, 11, 217, 191, 218, 192,
	197,
	196, 196, 196, 196, 196, 195, 180, 193, 194, 179, 243, 242, 227,
	216, 156, 7
};

static char defpalette[48] = {	/* Default color palette */
  0x00, 0x00, 0x00,
  0x00, 0x00, 0xAA,
  0x00, 0xAA, 0x00,
  0x00, 0xAA, 0xAA,
  0xAA, 0x00, 0x00,
  0xAA, 0x00, 0xAA,
  0xAA, 0x55, 0x00,
  0xAA, 0xAA, 0xAA,
  0x55, 0x55, 0x55,
  0x55, 0x55, 0xFF,
  0x55, 0xFF, 0x55,
  0x55, 0xFF, 0xFF,
  0xFF, 0x55, 0x55,
  0xFF, 0x55, 0xFF,
  0xFF, 0xFF, 0x55,
  0xFF, 0xFF, 0xFF
};

static char paletteregs[17] = {	/* Palette register list */
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x14, 0x07,
  0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F,
  0x00
};

static struct SaveCursorStruct {	/* Structure to save cursor description */
	int cursx;		/* X cursor position, column */
	int cursy;		/* Y cursor position, row */
	int *GL;		/* pointer to mapped character set */
	int G0;			/* character set G0 */
	int G1;			/* character set G1 */
	int mode;		/* origin mode */
} save = {
1, 1, &G0, ASCII, ASCII, 0};

/****************************************************************************/
/****************************************************************************/

/* I N T E R R U P T 1 0  -- Call on the BIOS video software interrupt */

static union REGS interrupt10(unsigned short ax, unsigned short bx,
		        unsigned short cx, unsigned short dx)
{
union REGS r;

        r.w.cx = cx;		/* Load contents of register parameters */
        r.w.dx = dx;
        r.w.bx = bx;
        r.w.ax = ax;
#if defined (__386__)
        int386(0x10, &r, &r);	/* Issue Video interrupt */
#else
        int86(0x10, &r, &r);	/* Issue Video interrupt */
#endif
	return(r);
}


/* B R K A T T R -- Break an attribute into its video components */

static void BrkAtt(unsigned char attribute)
{

	extrattr = 0;		/* Clear extra attributes */
	baseattr = attribute;	/* Start specified base attribute */

	if(vidmode == 0x7) {	/* If a Monochrome monitor */
		if(attribute & att_low_mask) {	/* Any Low mask attributes on? */
			baseattr |= att_normal;	/* if yes then set normal bits on */
		} else {	/* else check other attributes */
			if(attribute & att_underline) {	/* Underline attribute ? */
				extrattr |= att_underline;	/* yes then set underline bit */
				if(attribute & 0x70)	/* Reverse video ? */
					baseattr &= ~att_underline;	/* If yes then clear underline */
				else	/* monochrome can't do both */
					baseattr |= att_normal;	/* Else set normal bits on */
			}
		}
	}

	if(baseattr & att_intensity)	/* If bold attribute is on */
		extrattr |= att_intensity;	/* then set intensity bit */

	if(baseattr & att_blink)	/* If blink attribute is on */
		extrattr |= att_blink;	/* then set blink bit */

	/* Turn off blink,bold in base attribute */
	baseattr &= ~(att_intensity + att_blink);
}


/* A D D A T R -- Build video attribute from base and extra attributes */

static unsigned char AddAtt(void)
{

	if(extrattr & att_underline)	/* If underline is requested */
		baseattr &= ~att_low_mask;	/* Clear low mask */

	return (baseattr | extrattr);	/* return the or'ed attributes */
}


/* S T A R T S C R E E N -- Updates 'screen' pointer to 'row' and 'col' pos. */

void StartScreen(register int row, register int col)
{

	scroff = ((row * columns) + col) * 2;	/* Calculate offset from beginning of */
						/* screen memory */

	/* Construct a far pointer to video memory */
	screen = MK_FP(scrseg, scroff);

}


/* V T P R I N T F -- print a formatted string to the video screen */

static int vtprintf(int row, int col, int reverse, char *strformat, ...)
{
	unsigned attr, nchars;
	va_list argptr;
	char str[132];
	char *sptr = str;

	if(reverse) {		/* If reversed attribute specified */
		attr = att_reverse;
	} else {		/* Else use normal attribute */
		attr = att_normal;
	}

	va_start(argptr, strformat);	/* Start variable length argument list */
	StartScreen(row, col);	/* Start a screen update */
	nchars = vsprintf(str, strformat, argptr);	/* Format the string */
	while (*sptr != '\0') {	/* Move the formatted string */
		*screen++ = *sptr++;	/* to video memory */
		*screen++ = attr;
	}
	va_end(argptr);		/* End the va_start */
	return (nchars);	/* Return number of characters written */
}


/* V E S A C H E C K -- Check if VESA BIOS is available */

void VESACheck(void)
{

union REGS r;
struct SREGS s;
 #if defined (__386__)
 short sel, seg;
 static struct rminfo {
     long EDI;
     long ESI;
     long EBP;
     long reserved_by_system;
     long EBX;
     long EDX;
     long ECX;
     long EAX;
     short flags;
     short ES,DS,FS,GS,IP,CS,SP,SS;
 } RMI;
 #else
  char *vesainfo;
 #endif

        /* Save original video mode */
        origvmode = peekb(0x40, 0x49);

        if(Configuration & NOVESA){
           vesa = 0;
	   return;
	}

#if defined (__386__)
        /* allocate conventional mem for transfer buffer */
        memset(&s, 0, sizeof(s));
        r.w.ax = 0x0100;
        r.w.bx = 256 >> 4;	/* number of paragraphs needed */
        int386(0x31, &r, &r);   
        seg = r.w.ax;
        sel = r.w.dx;
        /* simulate real mode interrupt */
        memset(&RMI, 0, sizeof(RMI));
        RMI.EAX = 0x4F00;
        RMI.ES = seg;
        RMI.EDI = 0;
        r.w.ax = 0x0300;
        r.h.bl = 0x10;
        r.h.bh = 0;
        r.w.cx = 0;
        s.ds = 0;
        s.es = FP_SEG(&RMI);
        r.x.edi = FP_OFF(&RMI);
        int386x(0x31, &r, &r, &s);
        r.x.ebx = RMI.EAX;
        r.w.ax = 0x0101;
        r.w.dx = sel;
        int386(0x31, &r, &r);   
        if(r.h.bl == 0x4F)
#else
        if((vesainfo = (char *)malloc(256)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
        s.es = FP_SEG(vesainfo);
        r.x.di = FP_OFF(vesainfo);
        r.x.ax = 0x4F00;
        int86x(0x10, &r, &r, &s);    /* Get VESA info first */
        free(vesainfo);
        if(r.h.al == 0x4F)
#endif
           vesa = 1;
        else
           vesa = 0;
}


/* Add a line to the scrollback buffer */

void SbkAddline(void)
{
char *p;

	/* shift all up a line */
	memcpy(scrollbuf, scrollbuf + 2 * columns,
			 vidpages * 2 * columns * lines - 2 * columns);

	/* add line to bottom */
	p = MK_FP(scrseg, statusline * 2 * columns);
	memcpy(scrollbuf + vidpages * 2 * columns * lines - 2 * columns,
			p, 2 * columns);
}


/*
 * Set video page
 * Scrollback is tricky. We keep the scrollback buffer in memory.
 * Page 0 is always the page where things happen. The scrollback
 * area is mapped to page 1. So if scrollback happens, screen content
 * from memory is copied to page 1 then we switch to page 1.
 * Page -1 and 'vidpages' is immediate jump to the happening page.
 */
void SbkSetPage(signed char page)
{
char *p;
short n;

   if(page == -1) /* jump to the page where things happen? */
      page = vidpages;

   if(page == actpage) /* don't bother if we already at the requested page */
      return;

   if(page == vidpages) /* jump to happening page */
      interrupt10(0x0500, 0, 0, 0);
   else { /* else scroll back */
      n = peekw(0x40, 0x4c);
      p = MK_FP(scrseg, n);
      memcpy(p, scrollbuf + page * 2 * columns * lines, 2 * columns * lines);
      interrupt10(0x0501, 0, 0, 0);
   }

   actpage = page;
}


/* Scroll back a page */
void SbkBack(void)
{
   if(actpage)
      SbkSetPage(actpage - 1);
}


/* Scroll forward a page */
void SbkForward(void)
{
   if(actpage < vidpages)
      SbkSetPage(actpage + 1);
}


/****************************************************************************/
/****************************************************************************/

/* S E T M O D E -- Set video mode */

void SetMode(void)
{
        if(vesa && vidmode) /* switch only if VESA is supported and
                               mode is given at command line */
           interrupt10(0x4F02, vidmode, 0, 0);
}


/****************************************************************************/
/****************************************************************************/

/* V I D P A R A M -- Get Video Size & Type parameters */

void VidParam(void)
{
union REGS r;

 struct SREGS s;
 #if defined (__386__)
 char *p;
 short sel, seg;
 static struct rminfo {
     long EDI;
     long ESI;
     long EBP;
     long reserved_by_system;
     long EBX;
     long EDX;
     long ECX;
     long EAX;
     short flags;
     short ES,DS,FS,GS,IP,CS,SP,SS;
 } RMI;
 #endif

char bptr;

	if(vesa){
	   r = interrupt10(0x4F03, 0, 0, 0);
	   vidmode = r.w.bx;  /* Save the video mode */
	} else {
//	   vidmode = peekb(0x40, 0x49);
	   r = interrupt10(0x0F00, 0, 0, 0);
	   vidmode = (unsigned short)r.h.al;  /* Save the video mode */
	}

	columns = peekw(0x40, 0x4A); /* Save the number of columns */

	/* First determine if snow is a problem and set segment */
	if(vidmode != 7){		/* Assume video adapter is snowy if */
		retracemode = 1;	/* it is not a MonoChrome */
		scrseg = 0xb800;
	} else
		scrseg = 0xb000;

	/* First query Video BIOS to see if */
        /* VGA is present, no "snow" problem on VGA */
	r = interrupt10(0x1A00, 0, 0, 0);
	if(r.h.al == 0x1A){		/* If VGA is detected */
		retracemode = 0;	/* No snow protection needed */
		isvga = 1;

#if defined (__386__)
                /* allocate conventional mem for transfer buffer */
                memset(&s, 0, sizeof(s));
                r.w.ax = 0x0100;
                r.w.bx = 4;	       /* number of paragraphs needed */
                int386(0x31, &r, &r);   
                seg = r.w.ax;
                sel = r.w.dx;

                /* simulate real mode interrupt */
                memset(&RMI, 0, sizeof(RMI));
                RMI.EAX = 0x1009;  /*  Read all palette registers */
                RMI.ES = seg;
                RMI.EDX = 0;
                r.w.ax = 0x0300;
                r.h.bl = 0x10;
                r.h.bh = 0;
                r.w.cx = 0;
		s.ds = 0;
                s.es = FP_SEG(&RMI);
                r.x.edi = FP_OFF(&RMI);
                int386x(0x31, &r, &r, &s);

                p = MK_FP(seg, 0);
                memcpy(paletteregs, p, 17);

                r.w.ax = 0x0101;
                r.w.dx = sel;
                int386(0x31, &r, &r);   
#else
		r.x.ax = 0x1009; /*  Read all palette registers */
		s.es = FP_SEG(paletteregs);
		r.x.dx = FP_OFF(paletteregs);
		int86x(0x10, &r, &r, &s); /* Issue BIOS video interrupt */
#endif
	} else {        /* Else look for an EGA */
		r = interrupt10(0x1200, 0xFF00, 0x000C, 0);
		if(r.h.cl < 0xC) {	/* If EGA is detected */
			bptr = peekb(0x40, 0x87);       /* Check BIOS data to see if the */
			if((bptr & 0x8) == 0)		/* EGA is the active adapter */
				retracemode = 0;	/* No snow protection required */
		}
	}

	/* Determine the default screen attributes */
	r = interrupt10(0x0800, 0, 0, 0);	/* Get video attribute at cursor pos */
	scbattr = r.h.ah;	/* Save this attribute */

	if(isvga) 
		lines = peekb(0x40, 0x84) + 1; /* Check BIOS data to see # of rows on screen */
	else
		lines = 25;   /* Lines = 25, (sorry no 43,50 lines) */

}

/* V I D I N I T  -- Initialize the video system */

void VidInit(char *username, char *remotehost)
{
	screenbot = lines - statusline;
				/* Bottom of screen is 24 if statusline */
	screentop = 1;		/* Top of screen is line 1 */

	att_normal = scbattr;
	BrkAtt(scbattr);	/* Break the attribute into base,extra */
	/* Reverse the foreground and background */
	baseattr = (baseattr >> 4 | baseattr << 4);
	att_reverse = AddAtt();	/* Put the attributes back together */
	/* in order to get reverse attribute */

	/* Clear screen to established attribute */
	interrupt10(0x0600, scbattr << 8, 0, (lines << 8) | (columns - 1));

        if(statusline){
        	/* Clear the top line setting it to reverse */
        	interrupt10(0x0600, att_reverse << 8, 0, columns - 1);
        	vtprintf(0, 0, 1, "%s@%s", username, remotehost);
        	/* Display the mode line in reverse */
        }

	if((scrollbuf = (char *)malloc(SCROLLBUFSIZE)) == NULL)
           fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
	memset(scrollbuf, 0, SCROLLBUFSIZE);
	vidpages = SCROLLBUFSIZE / (2 * columns * lines);;
	actpage = vidpages;
}


/* V I D U N I N I T -- free buffers */
void VidUninit(void)
{
        free(scrollbuf);
	if(origvmode != vidmode)
           interrupt10(origvmode & 0xff, 0, 0, 0);
}


/* S E T V A T T R  --  Set the video attribute */

void SetVattr(unsigned char attr)
{

	video_state = 0;	/* Reset the video state */
	BrkAtt(scbattr);	/* Break apart the default screen attribute */

	switch (attr) {		/* See what video attribute is requested */
	case BLINK:		/* Blinking characters */
		extrattr = att_blink;
		break;
	case REVERSE:		/* Reversed video characters */
		video_state = 1;
		baseattr = (baseattr >> 4 | baseattr << 4);
		break;
	case UNDERLINED:	/* Underlined characters */
		if(vidmode == 0x7)	/* Monochrome can underline */
			extrattr = att_underline;
		else {		/* others can't use reverse video */
			video_state = 1;
			baseattr = (baseattr >> 4 | baseattr << 4);
		}
		break;
	case BOLD:		/* High intensity, bold, characters */
		extrattr = att_intensity;
		break;
	case NORMAL:		/* Normal characters */
	default:
		extrattr = 0;
		break;
	}
	curattr = AddAtt();	/* Put the video attributes back together */

}

/* A D D V A T T R  --  Add an attribute bit to the current video attribute */

void AddVattr(unsigned char attr)
{

	BrkAtt(curattr);	/* Break apart the current video attribute */

	switch (attr) {		/* See what attribute wants to be added */
	case BLINK:		/* Blinking attribute */
		extrattr |= att_blink;
		break;
	case BOLD:		/* High intensity, bold, attribute */
		extrattr |= att_intensity;
		break;
	case REVERSE:		/* Reversed attribute */
		if(video_state == 0) {
			video_state = 1;
			baseattr = (baseattr >> 4 | baseattr << 4);
		}
		break;
	case UNDERLINED:	/* Underlined characters */
		if(vidmode == 0x7)	/* Monochrom can underline */
			extrattr = att_underline;
		/* others cant use reversed video */
		else if(video_state == 0) {
			video_state = 1;
			baseattr = (baseattr >> 4 | baseattr << 4);
		}
		break;
	default:
		break;
	}
	curattr = AddAtt();	/* Put the video attributes back together */
}

/* S U B V A T T R  --  Remove attribute bit to the current video attribute */

void SubVattr(unsigned char attr)
{

	BrkAtt(curattr);	/* Break apart the current video attribute */

	switch (attr) {		/* See what video attribute to remove */
	case BLINK:		/* Remove the blinking attribute */
		extrattr &= ~att_blink;
		break;
	case BOLD:		/* Remove the high intensity, bold */
		extrattr &= ~att_intensity;
		break;
	case REVERSE:		/* Remove reversed attribute */
		if(video_state == 1) {
			video_state = 0;
			baseattr = (baseattr >> 4 | baseattr << 4);
		}
		break;
	case UNDERLINED:	/* Remove underlined attribute */
		if(vidmode == 0x7)	/* Monochrome could have underlined */
			extrattr &= ~att_underline;
		/* others couldn't remove reverse attribute */
		else if(video_state == 1) {
			video_state = 0;
			baseattr = (baseattr >> 4 | baseattr << 4);
		}
		break;
	default:
		break;
	}
	curattr = AddAtt();	/* Put the video attributes back together */
}

/* P O S C U R S -- Position the cursor on the physical screen */

static void PosCurs(void)
{
	register int col = cursx;
	register int row = cursy;

	if(!statusline) row--;/* up a line if no statusline */

	if(col > columns)	/* Check validity of requested column */
		col = columns;	/* put cursor on the right bound */

	if(row > lines)	/* Check validity of requested row */
		row = lines;	/* put cursor on the bottom */

	if(cursorvisible)	/* Only position the cursor if its visible */
		interrupt10(0x0200, 0, 0, (row << 8) | --col);
}


/* L I N E R I G H T -- Scroll line to right from cursor */

void LineRight(void)
{
unsigned char c[2], attr[2];
int row, ws;

	row=cursy;
	if(!statusline) row--;

	StartScreen(row, cursx - 1);	/* Start direct video memory access        */

	c[0] = *screen;	/* Save character at current position      */
	attr[0] = *(screen + 1);	/* Save attribute at current position      */
	*screen = ' '; /* clear inserted character */

	ws = 1;
	for (row = cursx; row < columns; row++) {

		c[ws] = *(screen + 2);	/* Save character at next position        */
		attr[ws] = *(screen + 3);	/* Save attribute at next position     */
		ws ^= 1;	/* Flop save char,attribute array index   */
		*(screen + 2) = c[ws];	/* Write saved character and attribute   */
		*(screen + 3) = attr[ws];
		screen += 2;	/* Increment to next character position   */
	}
}


/* S E T C U R S -- Set absolute cursor position on the logical screen */

void SetCurs(register int col, register int row)
{
	if(col == 0)		/* If called with X coordinate = zero */
		col = cursx;	/* then default to current coordinate */
	if(row == 0)		/* If called with Y coordinate = zero */
		row = cursy;	/* then default to current coordinate */

	if(originmode) {	/* If origin mode is relative */
		row += (scrolltop - 1);	/* adjust the row */
		if(row < scrolltop || row > scrollbot)
			return;	/* Can not position cursor out of scroll */
		/* region in relative cursor mode */
	}
	/* Can only position the cursor if it lies */
	/* within the logical screen limits */
	if(col > screenwid)
	   col = screenwid;
	if(row > screenbot)
	   row = screenbot;

	cursx = col;	/* Set the X cursor coordinate, column */
	cursy = row;	/* Set the Y cursor coordinate, row */
	PosCurs();	/* Request the physical positioning */
}


/* S E T S C R O L L  -- Establish the scrolling boundaries */

void SetScroll(register int top, register int bottom)
{

	if(top == 0)		/* If the top scroll boundary is 0 */
		top = 1;	/* interpret this as the top screen row */
	if(bottom == 0)	/* If the bottom scroll boundary is 0 */
		bottom = screenbot;	/* interpret this as bottom screen row */

	/* Set scrolling region if valid coords */
	if(top > 0 && top <= screenbot && bottom >= top
	    && bottom <= screenbot) {
		scrolltop = top;	/* save top boundary */
		scrollbot = bottom;	/* save bottom boundary */
		SetCurs(1, 1);	/* this also homes the cursor */
	}
}

/* I N D E X D O W N  -- Scroll the screen down */

void IndexDown(void)
{
	register unsigned attr;
	register unsigned top;
	register unsigned bottom;

	top=scrolltop;
	bottom=scrollbot;
	if(!statusline){
		top--;	/* up a line if no statusline */
		bottom--;
	}

	attr = scbattr << 8;	/* Get the attribute for new line */
	/* Call the BIOS to scroll the region */
	interrupt10(0x0701, attr, top << 8,
		    (bottom << 8) | (columns - 1));
	PosCurs();		/* Position the cursor */
}


/* I N D E X U P  -- Scroll the screen up */

void IndexUp(void)
{
	register unsigned attr;
	register unsigned top;
	register unsigned bottom;

	top=scrolltop;
	bottom=scrollbot;
	if(!statusline){
		top--;	/* up a line if no statusline */
		bottom--;
	}

	attr = scbattr << 8;	/* Get the attribute for new line */
	/* Call the BIOS to scroll the region */
	interrupt10(0x0601, attr, top << 8,
		    (bottom << 8) | (columns - 1));
	PosCurs();		/* Position the cursor */
}


/* S C R O L L D O W N  -- Move up a row scrolling if necessary */

void ScrollDown(void)
{

	if(cursy == scrolltop)	/* If on the top of the scrolling region */
		IndexDown();	/* scroll the rest of the region down */
	else {			/* Else */
		--cursy;	/* just decrement cursor Y position */
		PosCurs();	/* and request the reposition */
	}
}


/* S C R O L L U P  -- Move down a row scrolling if necessary */

void ScrollUp(void)
{

	if(cursy == scrollbot)	/* If on the bottom of the scrolling region */
		IndexUp();	/* scroll the rest of the region down */
	else {			/* Else */
		++cursy;	/* just increment the cursor Y position */
		PosCurs();	/* and request the reposition */
	}
}


/* W R I T E O N E C H A R -- writes on character to video memory      */

void WriteOneChar(unsigned char c, register int row, register int col)
{
	if(!statusline)
	   row--;	/* up a row if no status line */

        if(Configuration & BIOS){
	   interrupt10(0x0200, 0, 0, (row << 8) | col);
	   interrupt10((0x09 << 8) | c, curattr, 1, 0);
        } else {
	   StartScreen(row, col);
	   *screen++ = c;	/* write character into screen memory */
	   *screen = curattr;	/* write attribute into screen memory */
	}
}


/* C H R W R I T E  -- Write a character to a row and column of the screen */

void ChrWrite(unsigned char chr)
{

   if(GlobalConfig.brailab){ /* Brailab PC adapter is on */
	fputc((int)chr, GlobalConfig.brailab);

	switch(chr){
		case '.':	/* delimiters */
		case ',':
		case ';':
		case ':':
		case '?':
		case '!':
		   CharCounter = 0;
		   fflush(GlobalConfig.brailab);
		   break;

		default:	/* non-delimiters */
		   CharCounter++; /* increment counter */
		   if(CharCounter >= 160){
			fputc((int)':', GlobalConfig.brailab);
			CharCounter = 0;
			fflush(GlobalConfig.brailab);
		   }
		   break;
	}
   }

	if(*GL == ASCII)	/* Check character set being used */
		;		/* if regular ASCII then char is OK */
	else if(*GL == SPECIAL) {	/* if using the special character */
		if(chr > 94 && chr < 128)	/* then translate graphics characters */
			chr = special_chars[chr - 95];
	} else if(*GL == UK) {	/* If using the UK character set */
		if(chr == '#')	/* then watch for the number sign */
			chr = 'œ';	/* translating it to British pound */
	}

	/* NOTE:  Inserting a character using this technique is *very* slow      */
	/* for snowy CGA systems                                                 */
	if(insertmode) LineRight();	/* If insert mode, scoot rest of line over */

	if(cursx > screenwid) {	/* If trying to go beyond the screen width */
		if(autowrap) {	/* when autowrap is on */
			ScrollUp();	/* scroll the screen up */
			SetCurs(1, 0);	/* set cursor to column 1 of next line */
		} else
			cursx = screenwid;	/* else put the cursor on right margin */
	}

	WriteOneChar(chr, cursy, cursx - 1);

	++cursx;		/* Increment the cursor X position */
	PosCurs();		/* Move the cursor to the new position */

}


/* C H R D E L E T E  -- Erase a character at current position, shift
   line to left */
void ChrDelete(void)
{
	int row;

		row = cursy;
		if(!statusline) row--;

		StartScreen(row, cursx - 1);	/* Start direct video memory access        */

		for (row = cursx; row < columns; row++, screen += 2) {
			*(screen) = *(screen + 2);
			*(screen + 1) = *(screen + 3);
		}

                *screen = 0; /* last pos is empty */
}

/* S E T R E L C U R S -- Set relative curs pos on the logical screen */

void SetRelCurs(register int col, register int row)
{

	if(col == 0)		/* If called with X coordinate = zero */
		col = cursx;	/* then default to current X coordinate */
	else{			/* Else */
		col = cursx + col;	/* add col value to X cursor position */
		if(col < 0)	/* correct it if negative */
		   col = 1;
                else if(col > screenwid) /* or too large */
		   col = screenwid;
	}

	if(row == 0)		/* If called with Y coordinate = zero */
		row = cursy;	/* then default to current Y coordinate */
	else{			/* Else */
		row = cursy + row;	/* add row value to Y cursor position */
	        if(row < 0)	/* correct it if negative */
		   row = 1;
		else if(row > screenbot) /* or too large */
		   row = screenbot;
	}

	if(originmode) {	/* If origin mode is relative */
		row += (scrolltop - 1);	/* adjust the row */
		if(row < scrolltop || row > scrollbot)
			return;	/* Can not position cursor out of scroll */
	}

	/* region in relative cursor mode */
	/* Can only position the cursor if it lies */
	/* within the logical screen limits */
	if(col > 0 && col <= screenwid && row > 0 && row <= screenbot) {
		cursy = row;	/* Set the X cursor coordinate, column */
		cursx = col;	/* Set the Y cursor coordinate, row */
		PosCurs();	/* Request the physical positioning */
	}
}


/* C L E A R B O X -- Clear a window on the screen with the specified attr */

void ClearBox(unsigned char left, unsigned char top,
	      unsigned char right, unsigned char bottom,
	      unsigned char attr)
{

	if(!statusline){
		top--;
		bottom--;
	}

	/* Use BIOS scroll window function to clear */
	interrupt10(0x0600, attr << 8,	/* a window to a specified attribute */
		    (top << 8) | (--left), (bottom << 8) | --right);
}

/* C L E A R S C R E E N -- Clear the screen setting it to a normal attr */

void ClearScreen(void)
{
	ClearBox(1, screentop, columns, screenbot, scbattr);
}


/* C L E A R E O L -- Clear to the end of the current line */

void ClearEOL(void)
{
	ClearBox(cursx, cursy, columns, cursy, curattr);
}


/* C L E A R E O S -- Clear from the cursor to the end of screen */

void ClearEOS(void)
{
	ClearEOL();		/* First clear to the End of the Line */
	if(cursy < screenbot)	/* Then clear every line below it */
		ClearBox(1, cursy + 1, columns, screenbot, scbattr);
}


/* C L E A R B O L -- Clear to the beginning of the current line */

void ClearBOL(void)
{
	ClearBox(1, cursy, cursx, cursy, curattr);
}


/* C L E A R B O S -- Clear from the cursor to the beggining of screen */

void ClearBOS(void)
{
	ClearBOL();		/* First clear to the Beginning of the Line */
	if(cursy > screentop)	/* Then clear every line above it */
		ClearBox(1, screentop, columns, cursy - 1, scbattr);
}


/* M A P C H A R S E T -- Map an established character set to current */

void MapCharSet(int charset)
{

	if(charset == 0)	/* If mapping G0 character set */
		GL = &G0;	/* Point the current char set,GL to G0 */
	else if(charset == 1)	/* If mapping G1 character set */
		GL = &G1;	/* Point the current char set,GL, to G1 */
}

/* S E T C H A R S E T -- Establish a character set */

void SetCharSet(int gset, unsigned char set)
{
	int *charset;

	if(gset == 0)		/* Check to see what character set is */
		charset = &G0;	/* going to be set */
	else if(gset == 1)
		charset = &G1;
	else
		return;		/* If not valid set then return */

	switch (set) {
	case 'B':		/* 'B' maps the character set to ASCII */
		*charset = ASCII;	/* this is the normal character set */
		break;
	case 'A':		/* 'A' maps the character set to UK */
		*charset = UK;	/* only difference between UK and ASCII */
		break;		/* is the pound sign,  # = œ */
	case '0':		/* '0' maps the character set to SPECIAL */
		*charset = SPECIAL;	/* this character set is the 'graphics' */
		break;		/* character set used for line drawing */
	default:
		;
	}
}

/* S A V E C U R S O R  --  Save the cursor description into memory */

void SaveCursor(void)
{

	save.cursx = cursx;	/* Save the X cursor position */
	save.cursy = cursy;	/* Save the Y cursor position */
	save.GL = GL;		/* Save the current mapped character set */
	save.G0 = G0;		/* Save G0 character set */
	save.G1 = G1;		/* Save G1 character set */
	save.mode = originmode;	/* Also save the origin mode */
}

/* R E S T O R E C U R S O R  --  Restore the cursor description from memory */

void RestoreCursor(void)
{

	cursx = save.cursx;	/* Restore the saved X cursor position */
	cursy = save.cursy;	/* Restore the saved Y cursor position */
	GL = save.GL;		/* Restore the saved mapped character set */
	G0 = save.G0;		/* Restore the saved G0 character set */
	G1 = save.G1;		/* Restore the saved G1 character set */
	originmode = save.mode;	/* Also restore the saved origin mode */
	PosCurs();		/* Then reposition the cursor */
}

/* S E T C U R S O R V I S I B I L I T Y -- Show/Hide the cursor */

void SetCursorVisibility(int mode)
{

	if(mode) {		/* If visible cursor is specified, then */
		cursorvisible = 1;	/* the cursor will shown at the */
		SetCurs(0, 0);	/* current cursor position */
	} else {		/* Else the cursor will not appear on the */
		cursorvisible = 0;	/* terminal screen */
		interrupt10(0x0200, 0, 0, lines << 8);
	}
}

void SetCursorShape(int size)
{
	int c, fonthigh = 14;

	if( isvga ) {
		switch (size) {

		case 0:
		case 2:		/* default crusor */
			c = ((fonthigh - 3) << 8) + (fonthigh - 2) ;
			break;

		case 1:		/* invisible */
			c = ((32 + (fonthigh - 3)) << 8) + (fonthigh - 2);
			break;

		default:
			c = (fonthigh - 2) - (size * 2);
			if( c < 1 )
				c = 1;
			c = (c << 8) + (fonthigh - 2);
			break;
		}
		interrupt10(0x0100, 0, c, 0);
	}
}

/* S E T B A C K G R O U N D -- Set the background attribute */

void SetBackGround(int mode)
{
	int reverse_screen = 0;	/* Flag to indicate screen is to be reversed */
	register int i;

	if(mode) {		/* If reversed background is specified, */
		if(reversebackground != 1) {	/* only reverse the screen if it is */
			reverse_screen = 1;	/* not already set to reverse */
			reversebackground = 1;
		}
	} else {		/* Else if normal background is specified */
		if(reversebackground != 0) {	/* only reverse the screen if it is */
			reverse_screen = 1;	/* currently set to reverse */
			reversebackground = 0;
		}
	}

	if(reverse_screen) {	/* If reverse screen flag is set */
		/* first save the contents of screen */

		StartScreen(0, 0);

		for (i = 0; i < lines * columns; i++) {
			screen++;
			BrkAtt(*screen);	/* Break attribute apart and reverse it */
			baseattr = (baseattr >> 4 | baseattr << 4);
			*screen++ = AddAtt();	/* Put attribute together as displayable */
		}

		BrkAtt(scbattr);	/* reverse the default character attr */
		baseattr = (baseattr >> 4 | baseattr << 4);
		scbattr = AddAtt();
		BrkAtt(curattr);	/* reverse the current character attr */
		baseattr = (baseattr >> 4 | baseattr << 4);
		curattr = AddAtt();
	}
}


/* S E T C O L O R P A L E T T E -- Set the specific color palette */
void SetColorPalette(unsigned char color, unsigned char* clrdef)
{
	unsigned char c, r, g, b;

	if( isvga ) {
		r = clrdef[0] >> 2;
		g = clrdef[1] >> 2;
		b = clrdef[2] >> 2;
		c = paletteregs[color & 0x0F];
		interrupt10(0x1010, c, (g << 8) + b, (r << 8));
	}
}


/* R E S E T C O L O R P A L E T T E -- Reset the color palette to default v.*/

void ResetColorPalette(void)
{
	int i;
	for ( i = 0; i <= 15; ++i ) {
		SetColorPalette(i, defpalette + i * 3);
	}
}

/* I N I T T A B S -- Initialize Tab stops to default settings */

void InitTabs(void)
{
	register int i;

	for (i = 1; i < 131; i++) {	/* Set tabs for mod 8 = 0 positions */
		if(i % 8)	/* 9, 17, 26 .... */
			deftabs[i + 1] = tabs[i + 1] = 0;	/* Zero indicates no tab here */
		else
			deftabs[i + 1] = tabs[i + 1] = 1;	/* One indicates a tab stop */
	}
}

/* D O T A B -- Perform a tab */

void DoTab(void)
{
	register int i;
	/* Look for next tab stop */
	for (i = cursx + 1; i <= screenwid; i++) {
		if(tabs[i] == 1) {	/* If a tab stop is found */
			SetCurs(i, cursy);	/* request cursor position here */
			return;	/* and finished */
		}
	}
}

/* S E T T A B S T O P  -- set a tab stop at the current cursor position */

void SetTabStop(void)
{

	tabs[cursx] = 1;	/* Mark current cursor position as tab stop */
}

/* C L E A R T A B S T O P  -- clear a tab stop at the current curs position */

void ClearTabStop(void)
{

	tabs[cursx] = 0;	/* Clear current cursor position tab stop */
}

/* C L E A R A L L T A B S  -- clear all tab stops */

void ClearAllTabs(void)
{
	/* Clear all of the tab stop marks */
	memset(tabs, '\0', sizeof(tabs));
}

/* S E T S C R E E N W I D T H -- set the screen width */

void SetScreenWidth(int width)
{


	if(width == 132 && !(vidmode == 0x109 || vidmode == 0x10b)){
					/* When the screen is set to 132 columns */
	   if(vesa){		/* only if VESA is available... */
		scrseg = 0xb800;
		screenwid = 132;	/* set the logical right boundary */
		columns = 132;		/* set the logical right boundary */
		if(lines == 25){
        	   interrupt10(0x4f02, 0x109, 0, 0); /* set VESA mode */
                   vidmode = 0x109;
		} else if(lines == 50){
        	   interrupt10(0x4f02, 0x10b, 0, 0); /* set VESA mode */
                   vidmode = 0x10b;
		}
	   } /* vesa */
        } /* if width != 132 */
	else if(width == 80 && !(vidmode == 3 || vidmode == 7 || vidmode == 0x108)){
					/* Else if the screen width is 80 */
		screenwid = 80;	/* set the logical right boundary */
		columns = 80;		/* set the logical right boundary */
		if(isvga){
		   scrseg = 0xb800;
		   if(vesa && lines == 60){
		      interrupt10(0x4F02, 0x108, 0, 0); /* set 80x60 mode */
                      vidmode = 0x108;
		   } else {
		      interrupt10(0x0003, 0, 0, 0); /* set 80x25 mode */
                      vidmode = 3;
		   }
		} /* isvga */
		else {
		   interrupt10(0x0007, 0, 0, 0); /* set 80x25 mode */
                   vidmode = 7;
		   scrseg = 0xb000;
		}
        }

	/* Setting the screen width also */
	ClearScreen();		/* Clears the screen */
	originmode = 0;		/* Sets the origin mode to absolute */
	SetScroll(0, 0);	/* Resets the scrolling region */
	SetCurs(1, 1);		/* Sets the cursor to the home position */

	vidpages = SCROLLBUFSIZE / (2 * columns * lines);;
	actpage = vidpages;
	memset(scrollbuf, 0, SCROLLBUFSIZE);
}

/*
 * Save screen. Give back allocated memory pointer and cursor position
 */
short savescreen(char **p)
{
union REGS r;

   StartScreen(0, 0);
   if((*p = (char *)malloc(columns * lines * 2)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   memcpy(*p, screen, columns * lines * 2);
   r = interrupt10(0x0300, 0, 0, 0);
   return(r.w.dx);
}

/*
 * Restore screen and cursor position
 */
void restorescreen(char *p, short pos)
{
   StartScreen(0, 0);
   memcpy(screen, p, columns * lines * 2);
   free(p);
   interrupt10(0x0200, 0, 0, pos);
}
