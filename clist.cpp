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


#include <ida.hpp>

#include "sig.hpp"
#include "hash.hpp"

/*------------------------------------------------*/
/* function : clist_init                          */
/* description: Initializes a chained list of     */
/*              signatures                        */
/*------------------------------------------------*/

clist_t * clist_init(slist_t * l)
{
	clist_t * cl;
	dsig_t * ds, * prev;
	size_t i;

	cl = (clist_t *)qalloc(sizeof(*cl));
	if (!cl) return NULL;

	cl->num = l->num;
	cl->sigs = NULL;
	cl->nmatch = 0;
	cl->msigs = NULL;

	prev = NULL;

	for(i=0; i<l->num; i++)
	{
		ds = (dsig_t *)qalloc(sizeof(*ds));
		ds->prev = prev;
		ds->next = NULL;
		ds->removed = false;
		ds->sig = l->sigs[i];

		if (prev)
			prev->next = ds;
		else
			cl->sigs = ds;

		prev = ds;
	}

	cl->pos = cl->sigs;

	return cl;
}


/*------------------------------------------------*/
/* function : clist_insert                        */
/* description: Inserts sig in sorted list        */
/*------------------------------------------------*/

int clist_insert(clist_t * cl, sig_t * s)
{
	dsig_t * ds, * prev, * cur;
	int ret;

	ds = (dsig_t *)qalloc(sizeof(*ds));
	if (!ds) return -1;

	ds->sig = s;
	ds->prev = NULL;
	ds->next = NULL;
	ds->removed = false;

	prev = NULL;
	cur = cl->sigs;
	while (cur)
	{
		// sig_compare is reversed
		ret = sig_compare(&s, &cur->sig) ;
		if (!ret && cur->sig->startEA == s->startEA)
			return -1;
			
		if (ret <= 0)
			break;

		prev = cur;
		cur = cur->next;
	}

	ds->prev = prev;
	ds->next = cur;

	if (!prev)
		cl->sigs = ds;
	else
		prev->next = ds;

	if (cur) cur->prev = ds;

	cl->num++;

	return 0;
}

/*------------------------------------------------*/
/* function : clist_insert_dsig                   */
/* description: Inserts dsig in matched list      */
/*------------------------------------------------*/

int clist_insert_dsig(clist_t * cl, dsig_t * ds)
{
	dsig_t * prev, * cur;
	int ret;

	ds->prev = NULL;
	ds->next = NULL;
	ds->removed = true;

	prev = NULL;
	cur = cl->msigs;
	while (cur)
	{
		// sig_compare is reversed
		ret = sig_compare(&ds->sig, &cur->sig) ;
		if (!ret && cur->sig->startEA == ds->sig->startEA)
			return -1;
			
		if (ret <= 0)
			break;

		prev = cur;
		cur = cur->next;
	}

	ds->prev = prev;
	ds->next = cur;

	if (!prev)
		cl->msigs= ds;
	else
		prev->next = ds;

	if (cur) cur->prev = ds;

	cl->nmatch++;

	return 0;
}



/*------------------------------------------------*/
/* function : clist_init                          */
/* description: Initializes a chained list of     */
/*              signatures with a list of xrefs   */
/*------------------------------------------------*/

clist_t * clist_init_from_refs(hsig_t * hsig, frefs_t * refs)
{
	clist_t * cl;
	fref_t * fl;
	sig_t * sig;

	cl = (clist_t *)qalloc(sizeof(*cl));
	if (!cl) return NULL;

	cl->num = 0;
	cl->nmatch = 0;
	cl->sigs = NULL;
	cl->pos = NULL;
	cl->msigs = NULL;

	if (!refs) return cl;

	fl = refs->list;

	while(fl)
	{
		sig = hash_find_ea(hsig, fl->ea);
		if (sig && sig_get_matched_type(sig) == DIFF_UNMATCHED)
			clist_insert(cl, sig);

		fl = fl->next;
	}

	cl->pos = cl->sigs;

	return cl;
}


/*------------------------------------------------*/
/* function : clist_remove                        */
/* description: Removes element from list         */
/*------------------------------------------------*/

void clist_remove(clist_t * cl, dsig_t * ds)
{
	if (ds->removed == true)
		return;

	if (ds->prev == NULL)
		cl->sigs = ds->next;
	else
		ds->prev->next = ds->next;

	if (ds->next != NULL)
		ds->next->prev = ds->prev;

	clist_insert_dsig(cl, ds);
}


/*------------------------------------------------*/
/* function : clist_reset                         */
/* description: Resets list position              */
/*------------------------------------------------*/

void clist_reset(clist_t * cl)
{
	cl->pos = cl->sigs;
}

