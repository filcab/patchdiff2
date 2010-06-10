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


#ifndef __PGRAPH_H__
#define __PGRAPH_H__

#include "sig.hpp"

typedef struct node_list * pnode_list;

struct node_list
{
	uval_t id;
	slist_t * sl;
	pnode_list next;
};

typedef struct node_list nlist_t;


struct graph_list
{
	int num;
	nlist_t * sl;

};

typedef struct graph_list glist_t;


void pgraph_display(slist_t *, slist_t *);
void pgraph_display_one(slist_t *);

#endif