#ifndef _VIDIO_H
#define _VIDIO_H

extern void VidInit(char *, char *);	/* Initialize console */
extern void VidUninit(void);		/* Uninitialize console */
extern void VidParam(void);		/* Get Screen Size */
extern void VESACheck(void);		/* Check VESA BIOS */
extern void SetMode(void);		/* Set video mode */
extern void SbkSetPage(char);
extern void SbkBack(void);
extern void SbkForward(void);
extern void SbkAddline(void);
extern short savescreen(char **p);
extern void restorescreen(char *p, short pos);
extern void SetVattr(unsigned char);	/* Set the video attribute */
extern void AddVattr(unsigned char);	/* Add attribute to current video attribute */
extern void SubVattr(unsigned char);	/* Sub attribute from current vid attribute */
extern void LineRight(void);            /* Scroll line to right from cursor */
extern void ChrWrite(unsigned char);	/* Write character to the screen */
extern void ChrDelete(void);		/* Erase character at current position */
extern void SetScroll(int, int);	/* Set the scrolling region */
extern void ScrollDown(void);		/* Move down a row scrolling if necessary */
extern void ScrollUp(void);		/* Move up a row scrolling if necessary */
extern void IndexDown(void);		/* Scroll the screen down */
extern void IndexUp(void);		/* Scroll the screen up */
extern void SetCurs(int, int);		/* Set the cursor to absolute coordinates */
extern void SetRelCurs(int, int);	/* Set the cursor to relative coordinates */
extern void ClearScreen(void);		/* Clear the terminal screen */
extern void ClearEOS(void);		/* Clear from cursor to end of screen */
extern void ClearBOS(void);		/* Clear from cursor to top of screen */
extern void ClearEOL(void);		/* Clear from cursor to end of line */
extern void ClearBOL(void);		/* Clear from cursor to start of line */
extern void ClearBox(unsigned char,	/* Clear a box on the video screen */
	      unsigned char, unsigned char, unsigned char, unsigned char);
extern void MapCharSet(int);		/* Map a character set */
extern void SetCharSet(int, unsigned char);	/* Set a character set */
extern void SaveCursor(void);		/* Save the cursor description */
extern void RestoreCursor(void);	/* Restore the cursor description */
extern void SetCursorVisibility(int);	/* Set the cursor visibility mode */
extern void SetBackGround(int);	/* Set background video attribute */
extern void SetColorPalette(unsigned char,	/* Set the specific color palette */
	unsigned char*);
extern void ResetColorPalette(void);	/* Reset the color palette to default */
extern void InitTabs(void);		/* Initialize the tab settings */
extern void DoTab(void);		/* Perform a tab */
extern void SetTabStop(void);		/* Set a tab stop at cursor position */
extern void ClearTabStop(void);	/* Clear a tab stop at the cursor position */
extern void ClearAllTabs(void);	/* Clear all the defined tab stops */
extern void SetScreenWidth(int);	/* Set the logical width of the screen */
extern void WriteOneChar(unsigned char,	/* Write one character to the screen */
		  int, int);
#endif
