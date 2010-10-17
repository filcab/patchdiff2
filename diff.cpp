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
#include <idp.hpp>
#include <graph.hpp>
#include <kernwin.hpp>

#include "hash.hpp"
#include "sig.hpp"
#include "diff.hpp"
#include "clist.hpp"
#include "display.hpp"
#include "backup.hpp"
#include "options.hpp"


/*------------------------------------------------*/
/* function : diff_init_hash                      */
/* description: Initializes a hash structure and  */
/*              creates successor xrefs           */
/*------------------------------------------------*/

hpsig_t * diff_init_hash(slist_t * sl)
{
	fref_t * fref;
	psig_t * sig;
	hpsig_t * h;
	size_t i;

	h = hash_init(sl->num);
	if (!h) return NULL;

	for(i=0; i<sl->num; i++)
	{
		if (hash_add_ea(h, sl->sigs[i]) < 0)
		{
			hash_free(h);
			return NULL;
		}
	}
	// adds xrefs
	for(i=0; i<sl->num; i++)
	{
		if (sl->sigs[i]->srefs)
		{
			fref = sl->sigs[i]->srefs->list;
			while (fref)
			{
				if (!fref->rtype)
				{
					sig = hash_find_ea(h, fref->ea);
					if (sig)
						sig_add_pref(sig, sl->sigs[i]->startEA, fref->type, DO_NOT_CHECK_REF);
				}

				fref = fref->next;
			}
		}

		if (sl->sigs[i]->prefs)
		{
			fref = sl->sigs[i]->prefs->list;
			while (fref)
			{
				if (!fref->rtype)
				{
					sig = hash_find_ea(h, fref->ea);
					if (sig)
						sig_add_sref(sig, sl->sigs[i]->startEA, fref->type, DO_NOT_CHECK_REF);
				}

				fref = fref->next;
			}
		}
	}

	return h;
}


/*------------------------------------------------*/
/* function : slist_init_crefs                    */
/* description: Initializes slist crefs           */
/*------------------------------------------------*/

int slist_init_crefs(slist_t * l)
{
	hpsig_t * h = NULL;
	clist_t * cl1, * cl2;
	size_t i;

	h = diff_init_hash(l); 
	if(!h) return -1;

	for (i=0; i<l->num; i++)
	{
		cl1 = clist_init_from_refs(h, sig_get_preds(l->sigs[i]));
		cl2 = clist_init_from_refs(h, sig_get_succs(l->sigs[i]));
		sig_set_crefs(l->sigs[i], SIG_PRED, cl1);
		sig_set_crefs(l->sigs[i], SIG_SUCC, cl2);
	}

	return 0;
}


/*------------------------------------------------*/
/* function : diff_engine_initialize              */
/* description: Initializes engine structures     */
/*------------------------------------------------*/

deng_t * diff_engine_initialize(slist_t * l1, slist_t * l2, options_t * opt)
{
	deng_t * eng;

	if (slist_init_crefs(l1) != 0) return NULL;
	if (slist_init_crefs(l2) != 0) return NULL;

	eng = (deng_t *)qalloc(sizeof(*eng));
	if (!eng) return NULL;

	eng->magic = 0x0BADF00D;
	eng->wnum = 0;

	eng->identical = 0;
	eng->matched = 0;
	eng->unmatched = l1->num + l2->num;

	eng->opt = opt;

	return eng;
}


/*------------------------------------------------*/
/* function : diff_engine_initialize              */
/* description: Initializes engine structures     */
/*------------------------------------------------*/

void diff_engine_free(deng_t * eng)
{
	if (eng->ilist) siglist_free(eng->ilist);
	if (eng->mlist) siglist_free(eng->mlist);
	if (eng->ulist) siglist_free(eng->ulist);

	qfree(eng);
}


/*------------------------------------------------*/
/* function : sig_equal                           */
/* description: Checks if 2 sigs are equal        */
/*------------------------------------------------*/

bool sig_equal(psig_t * s1, psig_t * s2, int type)
{
	if (s1->sig != s2->sig || s1->hash != s2->hash)
		return false;

	if (type == DIFF_EQUAL_SIG_HASH_CRC_STR)
	{
		if (s1->str_hash != s2->str_hash)
			return false;
	}

	if (type <= DIFF_EQUAL_SIG_HASH_CRC)
	{
		if (s1->crc_hash != s2->crc_hash)
			return false;
	}

	return true;
}


/*------------------------------------------------*/
/* function : sig_name_equal                      */
/* description: Checks if 2 sig names are equal   */
/*------------------------------------------------*/

bool sig_name_equal(psig_t * s1, psig_t * s2)
{
	if (!strncmp(s1->name, "sub_", 4) || strcmp(s1->name, s2->name))
		return false;

	return true;
}

/*------------------------------------------------*/
/* function : clist_equal_match                   */
/* description: Checks if all the elements of a   */
/*              clist match                       */
/*------------------------------------------------*/

bool clist_equal_match(clist_t * cl1, clist_t * cl2)
{
	dpsig_t * s1, * s2;
	size_t i;

	if (!cl1 || !cl2 || cl1->nmatch == 0 || cl2->nmatch == 0)
		return false;

	if (cl1->nmatch != cl2->nmatch)
		return false;

	s1 = cl1->msigs;
	s2 = cl2->msigs;

	for (i=0; i<cl1->nmatch; i++)
	{
		if ((sig_get_matched_type(s1->sig) == DIFF_UNMATCHED) || (s1->sig->msig->startEA != s2->sig->startEA))
			return false;

		s1 = s1->next;
		s2 = s2->next;
	}

	return true;
}


/*------------------------------------------------*/
/* function : clist_almost_equal_match            */
/* description: Checks if at lest one element of a*/
/*              clist match                       */
/*------------------------------------------------*/

bool clist_almost_equal_match(clist_t * cl1, clist_t * cl2)
{
	dpsig_t * s1, * s2;
	size_t i, k;

	if (!cl1 || !cl2 || cl1->nmatch == 0 || cl2->nmatch == 0)
		return false;

	if (cl1->nmatch != cl2->nmatch)
		return false;

	s1 = cl1->msigs;


	for (i=0; i<cl1->nmatch; i++)
	{
		s2 = cl2->msigs;

		for (k=0; k<cl2->nmatch; k++)
		{
			if (s1->sig->msig->startEA == s2->sig->startEA)
				return true;

			s2 = s2->next;
		}

		s1 = s1->next;
	}

	return false;
}


/*------------------------------------------------*/
/* function : clist_get_unique_sig                */
/* description: Returns first unique signature in */
/*              list starting at ds				  */
/* note: changes ds if ds already matched         */
/*------------------------------------------------*/

dpsig_t * clist_get_unique_sig(clist_t * cl, dpsig_t ** ds, int type)
{
	dpsig_t * ptr, * tmp;

	if (!*ds) return NULL;
	ptr = *ds;

	// do not keep the current signature if not unique
	while (ptr)
	{
		if (sig_get_matched_type(ptr->sig) != DIFF_UNMATCHED)
		{
			if (ptr == *ds)
			{
				*ds = ptr->next;
				if (!*ds) return NULL;
			}

			tmp = ptr->next;
			clist_remove(cl, ptr);
			ptr = tmp;
		}
		else
		{
			if (!ptr->next) break;

			if (type == DIFF_NEQUAL_SUCC)
			{
				if (sig_equal(ptr->sig, (*ds)->sig, type) && sig_equal(ptr->next->sig, (*ds)->sig, type))
					return NULL;

				if (( (!sig_equal(ptr->next->sig, (*ds)->sig, type) && (!ptr->prev || !sig_equal(ptr->prev->sig, (*ds)->sig, type))) || !clist_equal_match((*ds)->sig->cs, ptr->next->sig->cs)) && ptr->sig->cs->nmatch > 0 &&  ptr->sig->cs->num == ptr->sig->cs->nmatch)
					break;
			}
			else if (type == DIFF_NEQUAL_PRED)
			{
				if (sig_equal(ptr->sig, (*ds)->sig, type) && sig_equal(ptr->next->sig, (*ds)->sig, type))
					return NULL;

				if (( (!sig_equal(ptr->next->sig, (*ds)->sig, type) && (!ptr->prev || !sig_equal(ptr->prev->sig, (*ds)->sig, type))) || !clist_equal_match((*ds)->sig->cp, ptr->next->sig->cp)) && ptr->sig->cp->nmatch > 0 && ptr->sig->cp->num == ptr->sig->cp->nmatch)
					break;
			}
			else if (type == DIFF_EQUAL_NAME)
			{
				if (!sig_equal(ptr->next->sig, (*ds)->sig, type) || !sig_name_equal((*ds)->sig, ptr->next->sig))
					break;
			}
			else if (type == DIFF_NEQUAL_STR)
			{
				bool b = false;
				tmp = *ds;

				if (ptr->sig->str_hash != 0)
				{
					// slow: need to improve
					while (tmp)
					{
						if (tmp->sig->startEA != ptr->sig->startEA && tmp->sig->str_hash == ptr->sig->str_hash)
						{
							b = true;
							break;
						}

						tmp = tmp->next;
					}

					if (!b)
						break;
				}
			}
			else
			{
				bool b = sig_equal(ptr->next->sig, (*ds)->sig, type);
				if (!b) break;
			}

			ptr = ptr->next;
		}
	}

	return ptr;
}

/*------------------------------------------------*/
/* function : clist_get_best_sig                  */
/* description: Returns best unique signature in  */
/*              list							  */
/* note: position pointer is incremented to the   */
/*       next signature in the list               */
/*------------------------------------------------*/

dpsig_t * clist_get_best_sig(clist_t * cl, int type)
{
	dpsig_t * best, * ptr;

	best = cl->pos;

	ptr = clist_get_unique_sig(cl, &best, type);

	// no more signature
	if (!best) return NULL;

	if (ptr == best)
	{
		cl->pos = best->next;
		return best;
	}

	cl->pos = ptr;
	return clist_get_best_sig(cl, type);
}


/*------------------------------------------------*/
/* function : clist_get_eq_sig                    */
/* description: Returns signature if sig presents */
/*              in list and unique                */
/*------------------------------------------------*/

dpsig_t * clist_get_eq_sig(clist_t * cl, dpsig_t * dsig, int type)
{
	dpsig_t * ds, * ptr;
	bool b2, b1 = sig_is_class(dsig->sig);

	ds = cl->sigs;
	while (ds)
	{
		if (type == DIFF_NEQUAL_SUCC)
		{
			ptr = clist_get_unique_sig(cl, &ds, type);
			if (!ds || !ptr) return NULL;
			
			b2 = sig_is_class(ptr->sig);
			if (b1 ^ b2) return NULL;

			if (clist_equal_match(ptr->sig->cs, dsig->sig->cs))
			{
				if (ptr->next && (ptr->next->sig->sig == ptr->sig->sig || clist_equal_match(ptr->next->sig->cs, dsig->sig->cs)))
					return NULL;

				return ptr;
			}
		}
		else if (type == DIFF_NEQUAL_PRED )
		{
			ptr = clist_get_unique_sig(cl, &ds, type);
			if (!ds || !ptr) return NULL;

			b2 = sig_is_class(ptr->sig);
			if (b1 ^ b2) return NULL;
			
			if (clist_equal_match(ptr->sig->cp, dsig->sig->cp))
			{
				if (ptr->next && (ptr->next->sig->sig == ptr->sig->sig || clist_equal_match(ptr->next->sig->cp, dsig->sig->cp)))
					return NULL;

				return ptr;
			}
		}
		else if (type == DIFF_EQUAL_NAME)
		{
			ptr = clist_get_unique_sig(cl, &ds, type);
			if (!ds || !ptr) return NULL;

			if (sig_name_equal(ptr->sig, dsig->sig))
				return ptr;
		}
		else if (type == DIFF_NEQUAL_STR)
		{
			ptr = clist_get_unique_sig(cl, &ds, type);
			if (!ds || !ptr) return NULL;

			if (ptr->sig->str_hash != 0 && ptr->sig->str_hash == dsig->sig->str_hash)
				return ptr;
		}
		else
		{
			if (sig_equal(ds->sig, dsig->sig, type))
			{
				ptr = clist_get_unique_sig(cl, &ds, type);

				if (!ds) return NULL;

				if (ptr != ds || !sig_equal(ds->sig, dsig->sig, type))
					return NULL;

				return ds;
			}
			else if (ds->sig->sig < dsig->sig->sig)
			{
				return NULL;
			}
		}

		ds = ds->next;
	}

	return NULL;
}


void clist_update_crefs(clist_t * cl, dpsig_t * ds, int type)
{
	dpsig_t * tmp, * next;
	dpsig_t * tmp2, * next2;
	clist_t * tcl;

	tmp = cl->sigs;
	while(tmp)
	{
		next = tmp->next;

		if (type == SIG_SUCC)
			tcl = tmp->sig->cs;
		else
			tcl = tmp->sig->cp;

		tmp2 = tcl->sigs;
		while(tmp2)
		{
			next2 = tmp2->next;

			if (tmp2->sig->startEA == ds->sig->startEA)
				clist_remove(tcl, tmp2);

			tmp2 = next2;
		}

		tmp = next;
	}
}


void clist_update_and_remove(clist_t * cl, dpsig_t * ds)
{
	if (ds->removed)
		return;

	clist_update_crefs(ds->sig->cp, ds, SIG_SUCC);
	clist_update_crefs(ds->sig->cs, ds, SIG_PRED);

	clist_remove(cl, ds);
}


/*------------------------------------------------*/
/* function : diff_run                            */
/* description: Runs binary analysis              */
/*------------------------------------------------*/

int diff_run(deng_t * eng, clist_t * cl1, clist_t * cl2, int min_type, int max_type, bool pclass)
{
	dpsig_t * dsig, * dsig2;
	int changed = 0;
	int type = min_type;
	int mtype = max_type;
	bool b;

	if (pclass && max_type > DIFF_EQUAL_SIG_HASH)
		mtype = DIFF_EQUAL_SIG_HASH;

	do
	{
		clist_reset(cl1);
		clist_reset(cl2);

		changed = 0;
		while (	(dsig = clist_get_best_sig(cl1, type)) != NULL)
		{
			clist_reset(cl2);
			dsig2 = clist_get_eq_sig(cl2, dsig, type);
			if (dsig2)
			{	
				sig_set_matched_sig(dsig->sig, dsig2->sig, type);

				eng->unmatched -= 2;
				if (dsig->sig->hash2 == dsig2->sig->hash2 || sig_equal(dsig->sig, dsig2->sig, DIFF_EQUAL_SIG_HASH))
					eng->identical++;
				else
					eng->matched++;

				changed = 1;

				clist_update_and_remove(cl1, dsig);
				clist_update_and_remove(cl2, dsig2);

				b = sig_is_class(dsig->sig);

				// string matching is not 100% reliable so we only match on crc/hash
				if (mtype == DIFF_NEQUAL_STR)
					b = true;

				diff_run(eng, sig_get_crefs(dsig->sig, SIG_PRED), sig_get_crefs(dsig2->sig, SIG_PRED), min_type, max_type, b);
				diff_run(eng, sig_get_crefs(dsig->sig, SIG_SUCC), sig_get_crefs(dsig2->sig, SIG_SUCC), min_type, max_type, b);

			}
		}

		if (changed == 0)
			type++;
	} while(type <= mtype);

	return 0;
}


/*------------------------------------------------*/
/* function : generate_diff                       */
/* description: Generates binary diff             */
/*------------------------------------------------*/

int generate_diff(deng_t ** d, slist_t * l1, slist_t * l2, char * file, bool display, options_t * opt)
{
	int ret;
	clist_t * cl1, * cl2;
	int un1, un2, idf, mf;
	deng_t * eng;

	eng = diff_engine_initialize(l1, l2, opt);
	if (eng == NULL)
		return -1;

	cl1 = clist_init(l1);
	cl2 = clist_init(l2);

	if (file)
		ret = diff_run(eng, cl1, cl2, DIFF_EQUAL_NAME, DIFF_NEQUAL_STR, false);
	else
	{
		ret = diff_run(eng, cl1, cl2, DIFF_EQUAL_SIG_HASH_CRC, DIFF_EQUAL_SIG_HASH, false);
		ret = diff_run(eng, cl1, cl2, DIFF_NEQUAL_PRED, DIFF_NEQUAL_STR, false);
	}

	if (display)
	{
		eng->mlist = siglist_init(eng->matched, file);
		eng->ulist = siglist_init(eng->unmatched, file);
		eng->ilist = siglist_init(eng->identical, file);

		un1 = un2 = idf = mf = 0;

		for (size_t i=0; i<l1->num; i++)
		{
			if (sig_is_class(l1->sigs[i]))
			{
				sig_free(l1->sigs[i]);
				continue;
			}

			if (sig_get_matched_type(l1->sigs[i]) == DIFF_UNMATCHED)
			{
				sig_set_nfile(l1->sigs[i], 1);
				siglist_add(eng->ulist, l1->sigs[i]);
				un1++;
			}
			else
			{
				if (l1->sigs[i]->hash2 == l1->sigs[i]->msig->hash2 || sig_equal(l1->sigs[i], l1->sigs[i]->msig, DIFF_EQUAL_SIG_HASH))
				{
					siglist_add(eng->ilist, l1->sigs[i]);
					idf++;
				}
				else
				{
					siglist_add(eng->mlist, l1->sigs[i]);
					mf++;
				}
			}
		}

		for (size_t i=0; i<l2->num; i++)
		{
			if (sig_is_class(l2->sigs[i]))
			{
				sig_free(l2->sigs[i]);
				continue;
			}

			if (sig_get_matched_type(l2->sigs[i]) == DIFF_UNMATCHED)
			{
				sig_set_nfile(l2->sigs[i], 2);
				siglist_add(eng->ulist, l2->sigs[i]);
				un2++;
			}
		}


		msg("Identical functions:   %d\n", idf);
		msg("Matched functions:     %d\n", mf);
		msg("Unmatched functions 1: %d\n", un1);
		msg("Unmatched functions 2: %d\n", un2);
		display_results(eng);
	}

	if (d)
		*d = eng;

	return 0;
}

