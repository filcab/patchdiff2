/* 
   Patchdiff2
   Portions (C) 2010 - 2011 Nicolas Pouvesle
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


#include "precomp.hpp"

#include "options.hpp"
#include "system.hpp"


static bool idaapi pdiff_menu_callback(void *ud)
{
	ushort option = 0, prev = 0;
	options_t * opt = (options_t *)ud;

	const char format[] =
			"STARTITEM 0\n"

			"PatchDiff2 options\n"
			"<##Settings #>\n"
			"<#Uses 'pipe' with the second IDA instance to speed up graph display#Keep second IDB open :C>\n"
			"<#Saves PatchDiff2 results into the current IDB#Save results to IDB :C>>\n\n"
			;

	option |= opt->ipc ? 1 : 0;
	option |= opt->save_db ? 2 : 0;
	prev = opt->ipc;

	if (AskUsingForm_c(format, &option))
	{
		opt->ipc = !!(option & 1);
		opt->save_db = !!(option & 2);

		if (prev && !option)
			ipc_close();
	}

	return true;
}


options_t * options_init()
{
	options_t * opt;
	int ipc, db;

	opt = (options_t *)qalloc(sizeof(*opt));
	if (!opt) return NULL;

	if (system_get_pref("IPC", (void *)&ipc, SPREF_INT))
		opt->ipc = !!ipc;
	else
		opt->ipc = true;

	if (system_get_pref("DB", (void *)&db, SPREF_INT))
		opt->save_db = !!db;
	else
		opt->save_db = true;

	add_menu_item("Options/", "PatchDiff2", NULL, SETMENU_APP, pdiff_menu_callback, opt);
  
	return opt;
}


void options_close(options_t * opt)
{
	del_menu_item("Options/PatchDiff2");
	if (opt) qfree(opt);
}


bool options_use_ipc(options_t * opt)
{
	return opt->ipc;
}


bool options_save_db(options_t * opt)
{
	return opt->save_db;
}
