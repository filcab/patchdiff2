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


#ifndef __HASH_H__
#define __HASH_H__

#include "sig.hpp"


typedef struct hsignature * phsignature;

struct hsignature
{
	psig_t * sig;
	phsignature next;
};

typedef struct hsignature hsignature_t;

struct hsig
{
	unsigned int max_hash;
	hsignature_t ** table ;
};

typedef struct hsig hpsig_t;


hpsig_t * hash_init(size_t);
unsigned int hash_mk_ea(hpsig_t *, ea_t);
int hash_add_ea (hpsig_t *, psig_t *);
psig_t * hash_find_ea (hpsig_t *, ea_t);
void hash_free (hpsig_t *);

#endif
