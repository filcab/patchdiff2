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


#ifndef __OPTIONS_H__
#define __OPTIONS_H__


struct p_options
{
	bool ipc;	// inter process communication
	bool save_db;
};

typedef struct p_options options_t;


options_t * options_init();
bool options_use_ipc(options_t *);
bool options_save_db(options_t *);
void options_close(options_t *);

#endif