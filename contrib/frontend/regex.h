/*
 * regex.h : External defs for Ozan Yigit's regex functions, for systems
 *	that don't have them builtin. See regex.c for copyright and other
 *	details.
 *
 * Note that this file can be included even if we're linking against the
 * system routines, since the interface is (deliberately) identical.
 *
 * George Ferguson, ferguson@cs.rochester.edu, 11 Sep 1991.
 */

#ifndef _REGEX_H
#define _REGEX_H

extern char *re_comp (char *pattern);
extern int   re_exec (char *lp);

#endif
