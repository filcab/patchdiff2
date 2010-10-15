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


#include <pro.h>
#include <ida.hpp>
#include <fpro.h>
#include <diskio.hpp>
#include <kernwin.hpp>

#include "sig.hpp"
#include "system.hpp"
#include "options.hpp"
#include "os.hpp"


// global variable to keep IPC state
ipc_config_t ipcc;


void system_temp_name(char * data, size_t size)
{
	char name[QMAXPATH];
	char * str;

	qtmpnam(name, sizeof(name));
	qsnprintf(data, size, "%s", name);

#ifndef __WINDOWS
	if (( str = getenv("TMPDIR")) == NULL) str = "/tmp";
	if (strncmp(name, "./", 2) == 0)
	  qsnprintf(data, size, "%s/%s", str, name);
#endif

	data[strlen(data)-4] = '\0';
}


/*------------------------------------------------*/
/* function : generate_idc_file                   */
/* description: generates an idc file to launch   */
/*              second plugin instance in batch   */
/*              mode                              */
/*------------------------------------------------*/

int generate_idc_file(char * file)
{
	FILE * fp;

	fp = qfopen(file, "w+");
	if (!fp) return -1;

	qfwrite(fp, PATCHDIFF_IDC, strlen(PATCHDIFF_IDC));
	qfclose(fp);

	return 0;
}


/*------------------------------------------------*/
/* function : system_execute_second_instance      */
/* description: Executes another IDA instance     */
/*------------------------------------------------*/

int system_execute_second_instance(char * idc, ea_t ea, char * file, bool close, long id, void * data)
{
	char path[QMAXPATH*4];
	char cmd[QMAXPATH*4];

	if (!getsysfile(path, sizeof(path), IDA_EXEC, NULL))
		return -1;

	if (generate_idc_file(idc))
		return -1;

	qsnprintf(cmd, sizeof(cmd), "%s -A -S\"%s\" -Opatchdiff2:%u:%"FMT_EA"u:%u:\"%s\" \"%s\"", 
									path,
									idc,
									id,
									ea,
									dto.graph.s_showpref,
									idc,
									file
									);

	return os_execute_command(cmd, close, data);
}


/*------------------------------------------------*/
/* function : ipc_init                            */
/* description: Inits interprocess communication  */
/*              between 2 IDA instances           */
/*------------------------------------------------*/

bool ipc_init(char * file, int type, long id)
{
	bool ret;
	long pid;
	char tmpname[QMAXPATH];

	if (type == 0)
	{
		ipcc.init = false;
		ipcc.data = NULL;
	}
	else if (!ipcc.init)
	{
		if (type == 1)
		{

			pid = os_get_pid();
			ret = os_ipc_init(&ipcc.data, pid, IPC_SERVER);
			if (!ret)
				return false;

			system_temp_name(tmpname, sizeof(tmpname));
			if (system_execute_second_instance(tmpname, BADADDR, file, false, pid, ipcc.data) != 0)
			{
				ipc_close();
				return false;
			}
		}
		else
		{
			ret = os_ipc_init(&ipcc.data, id, IPC_CLIENT);
			if (!ret)
				return false;
		}

		ipcc.init = true;
	}

	return true;
}


/*------------------------------------------------*/
/* function : ipc_close                           */
/* description: Closes interprocess communication */
/*              between 2 IDA instances           */
/*------------------------------------------------*/

void ipc_close()
{
	if (!ipcc.init) return;

	os_ipc_close(ipcc.data);

	ipcc.data = NULL;
	ipcc.init = false;
}


/*------------------------------------------------*/
/* function : ipc_send_cmd                        */
/* description: Executes command on the remote    */
/*              IDA instance                      */
/*------------------------------------------------*/

bool ipc_send_cmd(char * cmd)
{
	idata_t d;

	d.cmd = IPC_DATA;
	qstrncpy(d.data, cmd, sizeof(d.data));

	if (!os_ipc_send(ipcc.data, IPC_SERVER, &d))
		return false;

	if (!os_ipc_recv(ipcc.data, IPC_SERVER, &d) || d.cmd != IPC_DONE)
		return false;

	return true;
}



/*------------------------------------------------*/
/* function : ipc_recv_cmd                        */
/* description: Receives command to execute       */
/*------------------------------------------------*/

bool ipc_recv_cmd(char * buf, size_t blen)
{
	bool ret;
	idata_t d;
	size_t len;

	memset(d.data, '\0', sizeof(d.data));

	ret = os_ipc_recv(ipcc.data, IPC_CLIENT, &d);
	if (!ret)
		return false;

	if (d.cmd != IPC_DATA)
		return false;

	len = strlen(d.data) + 1;
	if (len > blen)
		len = blen;

	memcpy(buf, d.data, len);

	return true;
}


/*------------------------------------------------*/
/* function : ipc_recv_cmd_end                    */
/* description: Acknowledges end of command       */
/*------------------------------------------------*/

bool ipc_recv_cmd_end()
{
	idata_t d;

	d.cmd = IPC_DONE;

	return os_ipc_send(ipcc.data, IPC_CLIENT, &d);
}


/*------------------------------------------------*/
/* function : ipc_execute_second_instance         */
/* description: Sends command to the second IDA   */
/*              instance                          */
/*------------------------------------------------*/

void ipc_execute_second_instance(char * idc, ea_t ea, char * file)
{
	char cmd[QMAXPATH*4];
	
	if (!ipc_init(file, 1, 0))
		return;

	qsnprintf(cmd, sizeof(cmd), "%u:%"FMT_EA"u:%u:%s", 
									0,
									ea,
									dto.graph.s_showpref,
									idc
									);

	ipc_send_cmd(cmd);
}


/*------------------------------------------------*/
/* function : system_parse_idb                    */
/* description: generates a list of signatures for*/
/*              another idb                       */
/*------------------------------------------------*/

slist_t * system_parse_idb(ea_t ea, char * file, options_t * opt)
{
	slist_t * sl = NULL;
	char tmpname[QMAXPATH];

	system_temp_name(tmpname, sizeof(tmpname));

	if (!options_use_ipc(opt))
		system_execute_second_instance(tmpname, ea, file, true, 0, NULL);
	else
		ipc_execute_second_instance(tmpname, ea, file);

	sl = siglist_load(tmpname);
	os_unlink(tmpname);

	return sl;
}


/*------------------------------------------------*/
/* function : system_get_pref                     */
/* description: Gets global system preference     */
/*------------------------------------------------*/

bool system_get_pref(char * name, void * data, int type)
{
	if (type == SPREF_INT)
	{
		return os_get_pref_int(name, (int *)data);
	}

	return false;
}

