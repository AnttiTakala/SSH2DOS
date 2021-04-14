#ifndef _KEYMAP_H
#define _KEYMAP_H

extern char *keymap_value(unsigned int scancode);
extern void keymap_init(const char *filename);
extern void keymap_uninit(void);

#endif
