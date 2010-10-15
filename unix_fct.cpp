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


#include <sys/types.h>
#include <sys/wait.h>

#include <ida.hpp>
#include <kernwin.hpp>

#include "unix_fct.hpp"
#include "system.hpp"


struct ipc_data
{
  int spipe;
  int rpipe;
  pid_t pid;
};

typedef struct ipc_data ipc_data_t;


/*------------------------------------------------*/
/* function : create_process                      */
/* description: fork/exec                         */
/*------------------------------------------------*/

pid_t create_process(char * cmd)
{
  pid_t pid;
  char * argv[4];
  char name[512];

  pid = fork();
  if (pid == 0)
    {
      qsnprintf(name, sizeof(name), "\"%s\"", cmd);
      argv[0] = "sh";
      argv[1] = "-c";
      argv[3] = name;
      argv[4] = NULL;

      execvp(argv[0], argv);
    }

  return pid;
}


/*------------------------------------------------*/
/* function : os_execute_command                  */
/* description: Executes a command by creating a  */
/*              new process                       */
/*------------------------------------------------*/

int os_execute_command(char * cmd, bool close, void * data)
{
  ipc_data_t * id = (ipc_data_t *)data;
  int ret = -1;
  int status;
  pid_t pid;

  pid = create_process(cmd);
  if (pid == -1) return -1;

  if (close)
    {
      /* we wait until the process finished (IE: sig file is generated) */
      if (waitpid(pid, &status, 0) == -1)
	return -1;
    }
  else
    id->pid = pid;

  return 0;
}


/*------------------------------------------------*/
/* function : os_check_process                    */
/* description: checks process state              */
/*------------------------------------------------*/

bool os_check_process(pid_t pid)
{
  if (kill(pid, 0))
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
  return (long)getpid();
}


/*------------------------------------------------*/
/* function : os_unlink                           */
/* description: removes a link to a file          */
/*------------------------------------------------*/

int os_unlink(const char * path)
{
  return unlink(path);
}


/*------------------------------------------------*/
/* function : os_ipc_send                         */
/* description: Sends data on pipe                */
/*------------------------------------------------*/

bool os_ipc_send(void * data, int type, idata_t * d)
{
  ipc_data_t * id = (ipc_data_t *)data;
  ssize_t num;

  num = write(id->spipe, d, sizeof(*d));
  if (num > 0) return true;

  return false;
}


/*------------------------------------------------*/
/* function : os_ipc_recv                         */
/* description: Receives data on pipe             */
/*------------------------------------------------*/

bool os_ipc_recv(void * data, int type, idata_t * d)
{
  ipc_data_t * id = (ipc_data_t *)data;
  fd_set rfds, efds;
  struct timeval tv;
  int ret;
  
  FD_ZERO(&rfds);
  FD_SET(id->rpipe, &rfds);

  FD_ZERO(&efds);
  FD_SET(id->rpipe, &efds);

  tv.tv_sec = 0;
  tv.tv_usec = 1000;

  if (id->pid)
    {
      while (1)
	{
	  ret = select(1, &rfds, NULL, &efds, &tv);
	  
	  if (ret > 0 && FD_ISSET(id->rpipe, &rfds))
	    break;
	  
	  if (ret < 0 || (ret > 0 && FD_ISSET(id->rpipe, &efds)) || !os_check_process(id->pid))
	    return false;
	}
    }
  else
    {
      ret = select(1, &rfds, NULL, &efds, &tv);
      if (!(ret > 0 && FD_ISSET(id->rpipe, &rfds)))
	return false;
    }
  
  read(id->rpipe, d, sizeof(*d));
  
  return true;
}


/*------------------------------------------------*/
/* function : os_ipc_init                         */
/* description: Inits interprocess communication  */
/*------------------------------------------------*/

bool os_ipc_init(void ** data, long pid, int type)
{
  char sname[512];
  char rname[512];
  ipc_data_t * id;

  id = (ipc_data_t *)qalloc(sizeof(*id));
  if (!id)
    return false;
  
  memset(id, '\0', sizeof(*id));
	
  qsnprintf(sname, sizeof(sname), "/tmp/pdiff2spipe%u", pid);
  qsnprintf(rname, sizeof(rname), "/tmp/pdiff2rpipe%u", pid);
  
  if (type == IPC_SERVER)
    {
      mkfifo(sname, 0666);
      id->spipe = open(sname, O_RDWR|O_NONBLOCK);
      if (id->spipe == -1) goto error;

      mkfifo(rname, 0666);
      id->rpipe = open(rname, O_RDWR|O_NONBLOCK);
      if (id->rpipe == -1) goto error;
    }
  else
    {
      id->spipe = open(rname, O_RDWR|O_NONBLOCK);
      if (id->spipe == -1) goto error;

      id->rpipe = open(sname, O_RDWR|O_NONBLOCK);
      if (id->rpipe == -1) goto error;
    }

  *data = (void *)id;
  return true;

error:
  if (id->spipe) close(id->spipe);
  if (id->rpipe) close(id->rpipe);
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

  if (id->spipe) close(id->spipe);
  if (id->rpipe) close(id->rpipe);

  /* TODO: unlink pipe */
  return true;
}


/*------------------------------------------------*/
/* function : os_get_pref_int                     */
/* description: Gets system preferences (integer) */
/*------------------------------------------------*/

bool os_get_pref_int(char * name, int * i)
{
  *i = 0;
  return false;
}
