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


#ifndef __DIFF_H__
#define __DIFF_H__

#include "sig.hpp"
#include "hash.hpp"
#include "options.hpp"


#define DIFF_EQUAL_NAME					0
#define DIFF_EQUAL_SIG_HASH_CRC			1
#define DIFF_EQUAL_SIG_HASH_CRC_STR		2
#define DIFF_EQUAL_SIG_HASH				3
#define DIFF_NEQUAL_PRED				4
#define DIFF_NEQUAL_SUCC				5
#define DIFF_NEQUAL_STR					6
#define DIFF_MANUAL						7


struct dengine
{
	int magic;
	int matched;
	int unmatched;
	int identical;
	slist_t * mlist;
	slist_t * ulist;
	slist_t * ilist;
	options_t * opt;
	int wnum;
};

typedef struct dengine deng_t;


int generate_diff(deng_t **, slist_t *, slist_t *, char *, bool, options_t *);
void diff_engine_free(deng_t *);
bool sig_equal(sig_t *, sig_t *, int);

#endif