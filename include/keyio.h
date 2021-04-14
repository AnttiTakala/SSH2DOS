#ifndef _KEYIO_H
#define _KEYIO_H

extern int ConChk(void);	/* Check the keyboard for keystrokes */
extern void DoKey(void);	/* Interpret a keypress */
extern void SetKeyPad(int);	/* Set the keypad to APPLICATION, NUMERIC */
extern void SetCursorKey(int);	/* Set the cursor key mode */

#endif
