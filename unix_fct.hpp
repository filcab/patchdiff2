/* 
   Patchdiff2
   Portions (C) 2010 Nicolas Pouvesle
   Portions (C) 2007 - 2009 Tenable Network Security, Inc.
   
   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License version 2 as 
   published by the Free Software Foundation.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


#ifndef __UNIX_FCT_H__
#define __UNIX_FCT_H__

#include "system.hpp"


#ifdef __EA64__
#define IDA_EXEC "idag64.exe"
#else
#define IDA_EXEC "idag.exe"
#endif


// Preference functions
bool os_get_pref_int(char *, int *);

// System functions
int os_execute_command(char *, bool, void *);
void os_copy_to_clipboard(char *);
long os_get_pid();
int os_unlink(const char *path);

// Shared memory functions
bool os_ipc_send(void *, int, idata_t *);
bool os_ipc_recv(void *, int, idata_t *);
bool os_ipc_init(void **, long, int);
bool os_ipc_close(void *);

#endif
