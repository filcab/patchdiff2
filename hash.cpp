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


#include <ida.hpp>

#include "hash.hpp"
#include "sig.hpp"


/*------------------------------------------------*/
/* function : hash_init                           */
/* description: Initializes hash table to NULL    */
/*------------------------------------------------*/

hpsig_t * hash_init(size_t num)
{
	unsigned int i;
	hpsig_t * hsig;
	static unsigned int primes[] = { 67, 251, 509, 1021, 2039, 4093, 8191, 16381, 32749, 65521, 131071, 262139, 524287, 1048573, 2097143 };

	for (i=0; i < ((sizeof(primes) / sizeof(unsigned int)) - 1); i++)
		if (primes[i] > (num/3)) break;

	hsig = (hpsig_t *)qalloc(sizeof(*hsig));
	if (!hsig) return NULL;

	hsig->max_hash = primes[i];
	hsig->table = (hsignature_t **) qalloc(hsig->max_hash * sizeof(*hsig->table));
	if (!hsig->table)
	{
		qfree(hsig);
		return NULL;
	}

	for (i = 0; i < hsig->max_hash; i++)
		hsig->table[i] = NULL;

	return hsig;
}


/*------------------------------------------------*/
/* function : hash_mk_ea                          */
/* description: Creates hash value                */
/*------------------------------------------------*/

unsigned int hash_mk_ea(hpsig_t * htable, ea_t val)
{
	char * ptr;
	unsigned int h = 0;
	int i;

	ptr = (char *) &val;

	for (i=0; i<sizeof(val); i++)
	{
		h += ptr[i];
		h += ( h << 10 );
		h ^= ( h >> 6 );
	}

	h += ( h << 3);
	h ^= ( h >> 11 );
	h += ( h >> 15 );

	return h % htable->max_hash;
}


/*------------------------------------------------*/
/* function : hash_add_ea                         */
/* description: Adds element to the hash table    */
/*------------------------------------------------*/

int hash_add_ea (hpsig_t * htable, psig_t * sig)
{
	int id = hash_mk_ea(htable, sig->startEA);
	hsignature_t * hsig = NULL; 

	hsig = (hsignature_t *)qalloc(sizeof(*hsig));
	if (!hsig) return -1;

	hsig->sig = sig;
	hsig->next = htable->table[id];
	htable->table[id] = hsig;

	return 0;
}


/*------------------------------------------------*/
/* function : hash_find_ea                        */
/* description: Finds element in the hash table   */
/*------------------------------------------------*/

psig_t * hash_find_ea (hpsig_t * htable, ea_t ea)
{
	if (ea == BADADDR)
		return NULL;

	int id = hash_mk_ea(htable, ea);
	hsignature_t * hsig;

	hsig = htable->table[id];

	while (hsig != NULL)
	{
		if (hsig->sig->startEA == ea)
			return hsig->sig;

		hsig = hsig->next;
	}

	return NULL;
}


/*------------------------------------------------*/
/* function : hash_free                           */
/* description: Frees hash table                  */
/*------------------------------------------------*/

void hash_free (hpsig_t * htable)
{
	unsigned int i;
	hsignature_t * hsig, * tmp;

	for (i = 0; i < htable->max_hash; i++)
	{
		hsig = htable->table[i];

		while (hsig != NULL)
		{
			tmp = hsig->next;
			qfree (hsig);

			hsig = tmp;
		}
	}

	qfree(htable);
}

