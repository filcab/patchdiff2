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


#include <windows.h>
#include <ida.hpp>
#include <kernwin.hpp>

#include "win_fct.hpp"
#include "system.hpp"


struct ipc_data
{
	HANDLE shared;
	idata_t * memory;
	HANDLE slock;
	HANDLE rlock;
	HANDLE process;
};

typedef struct ipc_data ipc_data_t;



/*------------------------------------------------*/
/* function : os_execute_command                  */
/* description: Executes a command by creating a  */
/*              new process                       */
/*------------------------------------------------*/

int os_execute_command(char * cmd, bool close, void * data)
{
	STARTUPINFO    si;
	PROCESS_INFORMATION  pi;
	int ret = -1;
	ipc_data_t * id = (ipc_data_t *)data;

	ZeroMemory( &si, sizeof(STARTUPINFO) );
	si.cb = sizeof(STARTUPINFO); 
	si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
	si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
	si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
	si.dwFlags |= STARTF_USESTDHANDLES;

	if (CreateProcess(
		NULL,
		cmd,             // command line
		NULL,            // process security
		NULL,            // thread security
		FALSE,           // inherit handles-yes
		0,               // creation flags
		NULL,            // environment block
		NULL,            // current directory
		&si,             // startup info
		&pi))            // process info (out)
	{
		if (close)
		{
			/* we wait until the process finished (IE: sig file is generated) */
			if (WaitForSingleObject( pi.hProcess, INFINITE ) == WAIT_OBJECT_0)
				ret = 0;

			CloseHandle(pi.hProcess);
		}
		else
		{
			id->process = pi.hProcess;
			ret = 0;
		}

		CloseHandle(pi.hThread);
	}

	return ret;
}


/*------------------------------------------------*/
/* function : os_check_process                    */
/* description: checks process state              */
/*------------------------------------------------*/

bool os_check_process(void * handle)
{
	DWORD exitcode;

	if (GetExitCodeProcess((HANDLE)handle, &exitcode) && exitcode == STILL_ACTIVE)
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : os_copy_to_clipboard                */
/* description: Copies data to clipboard          */
/*------------------------------------------------*/

void os_copy_to_clipboard(char * data)
{
}


/*------------------------------------------------*/
/* function : os_get_pid                          */
/* description: Returns process ID                */
/*------------------------------------------------*/

long os_get_pid()
{
	return (long)GetCurrentProcessId();
}


/*------------------------------------------------*/
/* function : os_unlink                           */
/* description: removes a link to a file          */
/*------------------------------------------------*/

int os_unlink(const char * path)
{
	return _unlink(path);
}


/*------------------------------------------------*/
/* function : os_ipc_send                         */
/* description: Sends data on pipe                */
/*------------------------------------------------*/

bool os_ipc_send(void * data, int type, idata_t * d)
{
	ipc_data_t * id = (ipc_data_t *)data;
	HANDLE lock;

	memcpy(id->memory, d, sizeof(*id->memory));

	lock = (type == IPC_SERVER) ? id->slock : id->rlock;

	return (bool)SetEvent(lock);
}


/*------------------------------------------------*/
/* function : os_ipc_recv                         */
/* description: Receives data on pipe             */
/*------------------------------------------------*/

bool os_ipc_recv(void * data, int type, idata_t * d)
{
	ipc_data_t * id = (ipc_data_t *)data;
	HANDLE lock;
	DWORD ret;

	lock = (type == IPC_SERVER) ? id->rlock : id->slock;
	
	if (id->process)
	{
		while (1)
		{
			ret = WaitForSingleObject((HANDLE)lock, 1000);
			
			if (ret == WAIT_OBJECT_0)
				break;

			if (ret != WAIT_TIMEOUT || !os_check_process(id->process))
				return false;
		}
	}
	else
	{
		if (WaitForSingleObject((HANDLE)lock, INFINITE) != WAIT_OBJECT_0)
			return false;
	}

	memcpy(d, id->memory, sizeof(*d));

	return true;
}


/*------------------------------------------------*/
/* function : os_ipc_init                         */
/* description: Inits interprocess communication  */
/*------------------------------------------------*/

bool os_ipc_init(void ** data, long pid, int type)
{
	char name[512];
	ipc_data_t * id;

	id = (ipc_data_t *)qalloc(sizeof(*id));
	if (!id)
		return false;

	memset(id, '\0', sizeof(*id));
	
	qsnprintf(name, sizeof(name), "pdiff2_slock%u", pid);
	id->slock = CreateEvent(NULL, false, false, name);
	if (!id->slock)
		goto error;

	qsnprintf(name, sizeof(name), "pdiff2_rlock%u", pid);
	id->rlock = CreateEvent(NULL, false, false, name);
	if (!id->rlock)
		goto error;

	qsnprintf(name, sizeof(name), "pdiff2_sharedmemory%u", pid);
	if (type == IPC_SERVER)
	{
		id->shared = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, sizeof(idata_t), name);
		if (!id->shared)
			goto error;
	}
	else
	{
		id->shared = OpenFileMapping(FILE_MAP_ALL_ACCESS,false,name);
		if (!id->shared)
			goto error;
	}

	id->memory = (idata_t *)MapViewOfFile(id->shared, FILE_MAP_ALL_ACCESS, 0, 0, sizeof(idata_t));
	if (!id->memory)
		goto error;

	*data = (void *)id;
	return true;

error:
	if (id->slock) CloseHandle(id->slock);
	if (id->rlock) CloseHandle(id->rlock);
	if (id->shared) CloseHandle(id->shared);
	qfree(id);
	return false;
}


/*------------------------------------------------*/
/* function : os_ipc_close                        */
/* description: Closes IPC                        */
/*------------------------------------------------*/

bool os_ipc_close(void * data)
{
	ipc_data_t * id = (ipc_data_t *)data;

	if (id->slock) {SetEvent(id->slock); CloseHandle(id->slock);}
	if (id->rlock) {SetEvent(id->rlock); CloseHandle(id->rlock);}
	if (id->memory) UnmapViewOfFile((void *)id->memory);
	if (id->shared) CloseHandle(id->shared);
	if (id->process) CloseHandle(id->process);

	return true;
}


/*------------------------------------------------*/
/* function : os_get_pref_int                     */
/* description: Gets system preferences (integer) */
/*------------------------------------------------*/

bool os_get_pref_int(char * name, int * i)
{
	HKEY key;
	DWORD type;
	DWORD size;
	int tmp;
	long ret;

	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SOFTWARE\\Tenable\\PatchDiff2", 0, KEY_READ, &key);
	if (ret != ERROR_SUCCESS)
		return false;

	size = sizeof(tmp);
	ret = RegQueryValueEx(key, name, NULL, &type, (LPBYTE)&tmp, &size);
	RegCloseKey(key);

	if (ret != ERROR_SUCCESS || type != REG_DWORD)
		return false;

	*i = tmp;
	return true;
}
