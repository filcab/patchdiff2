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


#ifndef __WIN_FCT_H__
#define __WIN_FCT_H__

#include "sig.hpp"
#include "hash.hpp"

clist_t * clist_init(slist_t *);
int clist_insert(clist_t *, sig_t *);
clist_t * clist_init_from_refs(hsig_t *, frefs_t *);
void clist_remove(clist_t *, dsig_t *);
void clist_reset(clist_t *);

#endif
