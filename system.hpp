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


#ifndef __SYSTEM_HPP__
#define __SYSTEM_HPP__

#include "sig.hpp"
#include "options.hpp"

#define PATCHDIFF_IDC "#include <idc.idc>\n\nstatic main (void)\n{\n	RunPlugin (\"patchdiff2\", 1);\n	Exit(1);\n}\n"

#define SPREF_INT 1

#define IPC_DATA 0
#define IPC_DONE 1
#define IPC_END  3

#define IPC_SERVER 1
#define IPC_CLIENT 2


struct idata
{
	long cmd;
	char data[256];
};

typedef struct idata idata_t;


struct ipc_config
{
	long init;
	void * data;
};

typedef struct ipc_config ipc_config_t;


bool system_get_pref(char *, void *, int);
slist_t * system_parse_idb(ea_t, char *, options_t *);

bool ipc_init(char *, int, long);
void ipc_close();
bool ipc_recv_cmd(char *, size_t);
bool ipc_recv_cmd_end();

#endif