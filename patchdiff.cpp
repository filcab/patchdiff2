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

#include "sig.hpp"
#include "parser.hpp"
#include "patchdiff.hpp"
#include "diff.hpp"
#include "backup.hpp"
#include "display.hpp"
#include "options.hpp"
#include "system.hpp"

extern plugin_t PLUGIN;
extern char *exename;

deng_t * d_engine;
cpu_t patchdiff_cpu;
options_t * d_opt;


static int idaapi init(void)
{
	if (!strcmp(inf.procName, "metapc"))
	{
		if (inf.is_64bit())
			patchdiff_cpu = CPU_X8664;
		else
			patchdiff_cpu = CPU_X8632;
	}
	else if (!strcmp(inf.procName, "PPC"))
	{
		patchdiff_cpu = CPU_PPC;
	}
	else
		patchdiff_cpu = CPU_DEFAULT;

	d_engine = NULL;
	
	// handle IPC
	ipc_init(NULL, 0, 0);

	d_opt = options_init();
	if (!d_opt)
		return PLUGIN_SKIP;

	return PLUGIN_OK;
}

static void idaapi term(void)
{
	if (d_engine)
	{
		if (options_save_db(d_opt))
			backup_save_results(d_engine);
		diff_engine_free(d_engine);
		unhook_from_notification_point(HT_UI, ui_callback);
	}

	ipc_close();
	options_close(d_opt);
}


static void run_first_instance()
{
	char * file;
	slist_t * sl1 = NULL;
	slist_t * sl2 = NULL;
	int ret;

	msg ("\n---------------------------------------------------\n"
		"PatchDiff Plugin v2.0.10\n"
		"Copyright (c) 2010-2011, Nicolas Pouvesle\n"
		"Copyright (C) 2007-2009, Tenable Network Security, Inc\n"
		"---------------------------------------------------\n\n");

	ret = backup_load_results(&d_engine, d_opt);
	if (ret == 1)
	{
		display_results(d_engine);
		return;
	}
	else if (ret == -1)
	{
		return;
	}

	show_wait_box ("PatchDiff is in progress ...");

	msg ("Scanning for functions ...\n");

	msg ("parsing second idb...\n");
	sl2 = parse_second_idb(&file, d_opt);
	if (!sl2)
	{
		msg("Error: IDB2 parsing cancelled or failed.\n");
		hide_wait_box();
		return;
	}

	msg ("parsing first idb...\n");
	sl1 = parse_idb ();
	if (!sl1)
	{
		msg("Error: IDB1 parsing failed.\n");
		siglist_free(sl2);
		hide_wait_box();
		return;
	}

	msg ("diffing...\n");
	generate_diff(&d_engine, sl1, sl2, file, true, d_opt);

	msg ("done!\n");
	hide_wait_box();

	if (sl1) siglist_partial_free(sl1);
	if (sl2) siglist_partial_free(sl2);
}


static void run_second_instance(const char * options)
{
	slist_t * sl;
	char file[QMAXPATH];
	ea_t ea = BADADDR;
	unsigned char opt = 0;
	long id;
	unsigned int v;
	bool cont;
	char tmp[QMAXPATH*4];
	
	qsscanf(options, "%u:%a:%u:%s", &id, &ea, &v, file);
	opt = (unsigned char)v;
	
	if (id)
	{
		if (ipc_init(file, 2, id))
		{
			do
			{
				cont = ipc_recv_cmd(tmp, sizeof(tmp));
				if (cont)
				{
					run_second_instance(tmp);
					ipc_recv_cmd_end();
				}

			}while(cont);
		}
	}
	else
	{
		if (ea == BADADDR)
		{
			sl = parse_idb ();
		}
		else
			sl = parse_fct(ea, opt);

		if (!sl) return;
		
		siglist_save(sl, file);

		siglist_free(sl);
	}
}


static void idaapi run(int arg)
{
	const char * options = NULL;

	autoWait();

	options = get_plugin_options("patchdiff2");

	if (options == NULL)
		run_first_instance();
	else
		run_second_instance(options);
}


char comment[] = "w00t";
char help[] = "A Binary Difference Analysis plugin module\n";
char wanted_name[] = "PatchDiff2";
char wanted_hotkey[] = "Ctrl-8";

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_MOD | PLUGIN_FIX,
	init,
	term,
	run,
	comment,
	help,
	wanted_name,
	wanted_hotkey
};
