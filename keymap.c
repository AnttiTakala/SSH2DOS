/* keymap.c       Copyright (c) 2001-2002 Shane Wegner
 *
 * $Date: 2005/12/30 16:26:40 $
 * $Revision: 1.3 $
 *
 * This module provides keymap support.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "common.h"
#if defined (MEMWATCH)
 #include "memwatch.h"
#endif

struct keymap {
   unsigned int scancode;
   char *value;
   struct keymap *next;
};

static struct keymap *keymaps = NULL;

char *keymap_value(unsigned int scancode)
{
struct keymap *k;

   for (k = keymaps; k != NULL; k = k->next)
	if (k->scancode == scancode)
		return k->value;
   return NULL;
}


void keymap_uninit(void)
{
struct keymap *k, *p;

   for (k = keymaps; k != NULL; ) {
      p = k;
      k = k->next;
      free(p->value);
      free(p);
   }
}


static void keymap_add(unsigned int scancode, const char *value)
{
struct keymap *k, *p = NULL;
unsigned char *v;

   if((v = (unsigned char*)malloc(strlen(value) + 1)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   strcpy(v, value);
   for (k = keymaps; k != NULL; k = k->next) {
	if (k->scancode == scancode) {
	   /* Just replace the current value and return */
	   free(k->value);
	   k->value = v;
	   return;
	   } /* if */
   p = k;
   } /* for */

   if((k = (struct keymap *)malloc(sizeof(struct keymap))) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

   k->scancode = scancode;
   k->value = v;
   k->next = NULL;
   if (p != NULL)
	p->next = k;
   else
	keymaps = k;

}

void keymap_init(const char *filename)
{
FILE *kf;
char *line, *newvalue;
char *cmd, *key, *value, *valptr, *endptr;
unsigned int scancode;
int i;

   if((kf = fopen(filename, "r")) == NULL)
	fatal("Cannot open keymap file");

   if((line = (char *)malloc(1024)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);
   if((newvalue = (char *)malloc(1024)) == NULL)
      fatal("Memory allocation error. %s: %d", __FILE__, __LINE__);

   while(fgets(line, 1024, kf) != NULL) {
	if (!*line)
	   continue;
	while (line[strlen(line) - 1] == '\n' || line[strlen(line) - 1] == '\r')
	   line[strlen(line) - 1] = 0;
	while (*line == ' ' || *line == '\t')
	   memmove(line, line+1, strlen(line));
	if (!*line || *line == '#')
	   continue;

	/* Now to the real work */
	if ((cmd = strtok(line, " ")) == NULL)
	   continue;
	if (!strcmp(cmd, "mapkey")){
	   if ((key = strtok(NULL, " ")) == NULL)
		continue;
	   if ((value = strtok(NULL, "\00")) == NULL)
		continue;
	   scancode = strtoul(key, NULL, 0);
	   if (!scancode)
		continue;
	   memset(newvalue, 0, 1024);
	   i = 0;
	   for (valptr = value; *valptr; valptr++) {
		if (*valptr == '\\') {
			valptr++;
			if (!*valptr)
			   break;
			switch(*valptr) {
				case '0':
				case '1':
				case '2':
				case '3':
				case '4':
				case '5':
				case '6':
				case '7':
				case '8':
				case '9': /* octal digit */
					newvalue[i++] = strtol(valptr, &endptr, 8);
					if (endptr != valptr)
						valptr = endptr - 1;
					break;

				case 'a': /* bell */
					newvalue[i++] = '\a';
					break;

				case 'e': /* escape */
				case 'E':
					newvalue[i++] = 0x1b;
					break;

				case 'n': /* newline */
					newvalue[i++] = '\n';
					break;

				case 't': /* tab */
					newvalue[i++] = '\t';
					break;

				default:
					newvalue[i++] = *valptr;
			} /* switch */
		} else
		newvalue[i++] = *valptr;
	   } /* for */
	   keymap_add(scancode, newvalue);
	} /* if mapkey */
   } /* while fgets */

   free(line);
   free(newvalue);

   fclose(kf);
}
