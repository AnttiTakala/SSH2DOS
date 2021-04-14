/* shell.c       Copyright (c) 2000-2003 Nagy Daniel
 *
 * $Date: 2005/12/30 16:26:41 $
 * $Revision: 1.4 $
 *
 * This module spawns a DOS shell
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
#include <conio.h>
#include <stdlib.h>
#include <string.h>
#include <direct.h>

#include "vidio.h"


/*
 * Spawn a DOS shell
 */
void Shell(void)
{
char *comspec;
char olddir[80];
char *p;
short pos;

   pos = savescreen(&p);
   getcwd(olddir, sizeof(olddir));
   cputs("\r\n\r\nType EXIT to quit from this shell\r\n");
   comspec = getenv("COMSPEC");
   system(comspec);
   chdir(olddir);
   restorescreen(p, pos);
}
