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


#include "precomp.hpp"

#include "sig.hpp"
#include "diff.hpp"
#include "options.hpp"
#include "backup.hpp"


static void buffer_serialize_data(char * buf, size_t blen, size_t * pos, void * data, size_t dsize)
{
	if ( (*pos + dsize) > blen)
	{
		*pos = blen;
		return;
	}

	memcpy(buf+*pos, data, dsize);
	*pos += dsize;
}


static void buffer_unserialize_data(char * buf, size_t blen, size_t * pos, void * data, size_t dsize)
{
	if ( (*pos + dsize) > blen)
	{
		*pos = blen;
		return;
	}

	memcpy(data, buf+*pos, dsize);
	*pos += dsize;
}


static void buffer_serialize_ea(char * buf, size_t blen, size_t * pos, ea_t ea)
{
	buffer_serialize_data(buf, blen, pos, &ea, sizeof(ea));
}


static void buffer_serialize_bool(char * buf, size_t blen, size_t * pos, bool b)
{
	buffer_serialize_data(buf, blen, pos, &b, sizeof(b));
}


static void buffer_serialize_char(char * buf, size_t blen, size_t * pos, char c)
{
	buffer_serialize_data(buf, blen, pos, &c, sizeof(c));
}


static void buffer_serialize_int(char * buf, size_t blen, size_t * pos, int i)
{
	buffer_serialize_data(buf, blen, pos, &i, sizeof(i));
}


static void buffer_serialize_long(char * buf, size_t blen, size_t * pos, unsigned long l)
{
	buffer_serialize_data(buf, blen, pos, &l, sizeof(l));
}


static void buffer_serialize_size(char * buf, size_t blen, size_t * pos, size_t size)
{
	buffer_serialize_data(buf, blen, pos, &size, sizeof(size));
}


static void buffer_unserialize_ea(char * buf, size_t blen, size_t * pos, ea_t * ea)
{
	buffer_unserialize_data(buf, blen, pos, ea, sizeof(*ea));
}


static void buffer_unserialize_bool(char * buf, size_t blen, size_t * pos, bool * b)
{
	buffer_unserialize_data(buf, blen, pos, b, sizeof(*b));
}


static void buffer_unserialize_char(char * buf, size_t blen, size_t * pos, char * c)
{
	buffer_unserialize_data(buf, blen, pos, c, sizeof(*c));
}


static void buffer_unserialize_int(char * buf, size_t blen, size_t * pos, int * i)
{
	buffer_unserialize_data(buf, blen, pos, i, sizeof(*i));
}


static void buffer_unserialize_long(char * buf, size_t blen, size_t * pos, unsigned long * l)
{
	buffer_unserialize_data(buf, blen, pos, l, sizeof(*l));
}


static void buffer_unserialize_size(char * buf, size_t blen, size_t * pos, size_t * size)
{
	buffer_unserialize_data(buf, blen, pos, size, sizeof(*size));
}


/*------------------------------------------------*/
/* function : buffer_serialize_string             */
/* description: Serializes a string               */
/*------------------------------------------------*/

static void buffer_serialize_string(char * buf, size_t blen, size_t * pos, char * s)
{
	size_t len;

	len = strlen(s) + 1;
	if ( (*pos + len) > blen)
	{
		*pos = blen;
		return;
	}

	memcpy(buf+*pos, s, len);
	*pos += len;
}


/*------------------------------------------------*/
/* function : buffer_unserialize_string           */
/* description: Unserializes a string             */
/*------------------------------------------------*/

static void buffer_unserialize_string(char * buf, size_t blen, size_t * pos, char ** s)
{
	*s = qstrdup(buf+*pos);
	*pos += strlen(*s) + 1;
}


/*------------------------------------------------*/
/* function : singleton_serialize                 */
/* description: Serializes a signature            */
/*------------------------------------------------*/

static size_t singleton_serialize(char * buf, size_t blen, psig_t * s, int nfile)
{
	size_t pos = 0;
	fref_t * fref = NULL;
	int num, i;

	buffer_serialize_ea(buf, blen, &pos, s->startEA);

	buffer_serialize_int(buf, blen, &pos, s->mtype);

	buffer_serialize_int(buf, blen, &pos, s->id_crc);
	buffer_serialize_int(buf, blen, &pos, nfile);

	buffer_serialize_long(buf, blen, &pos, s->sig);
	buffer_serialize_long(buf, blen, &pos, s->hash);
	buffer_serialize_long(buf, blen, &pos, s->crc_hash);
	buffer_serialize_long(buf, blen, &pos, s->str_hash);
	buffer_serialize_int(buf, blen, &pos, s->flag);
	buffer_serialize_long(buf, blen, &pos, s->lines);

	num= 0;
	if (s->srefs)
	{
		fref = s->srefs->list;
		num = s->srefs->num;
	}

	buffer_serialize_int(buf, blen, &pos, num);
	for (i=0; i<num; i++)
	{
		buffer_serialize_ea(buf, blen, &pos, fref->ea);
		buffer_serialize_int(buf, blen, &pos, fref->type);

		fref = fref->next;
	}

	if (nfile == 2)
	{
		if (!strncmp(s->name, "sub_", 4))
		{
			buffer_serialize_char(buf, blen, &pos, 0);
		}
		else
		{
			buffer_serialize_char(buf, blen, &pos, 1);
			buffer_serialize_string(buf, blen, &pos, s->name);
		}
	}

	return pos;
}


/*------------------------------------------------*/
/* function : singleton_unserialize                 */
/* description: Serializes a signature            */
/*------------------------------------------------*/

static size_t singleton_unserialize(char * buf, size_t blen, psig_t ** s, int version)
{
	char tmp[512];
	size_t pos = 0;
	char c;
	int num, i;
	ea_t ea;
	int type;

	*s = sig_init();
	if (!(*s)) return 0;

	buffer_unserialize_ea(buf, blen, &pos, &(*s)->startEA);

	buffer_unserialize_int(buf, blen, &pos, &(*s)->mtype);

	buffer_unserialize_int(buf, blen, &pos, &(*s)->id_crc);
	buffer_unserialize_int(buf, blen, &pos, &(*s)->nfile);

	buffer_unserialize_long(buf, blen, &pos, &(*s)->sig);
	buffer_unserialize_long(buf, blen, &pos, &(*s)->hash);
	buffer_unserialize_long(buf, blen, &pos, &(*s)->crc_hash);
	
	if (version >= 2)
		buffer_unserialize_long(buf, blen, &pos, &(*s)->str_hash);
	if (version >= 3)
		buffer_unserialize_int(buf, blen, &pos, &(*s)->flag);

	buffer_unserialize_long(buf, blen, &pos, &(*s)->lines);

	buffer_unserialize_int(buf, blen, &pos, &num);
	for (i=0; i<num; i++)
	{
		buffer_unserialize_ea(buf, blen, &pos, &ea);
		buffer_unserialize_int(buf, blen, &pos, &type);

		sig_add_sref(*s, ea, type, CHECK_REF);
	}


	if ((*s)->nfile == 2)
	{
		buffer_unserialize_char(buf, blen, &pos, &c);
		
		if (c == 1)
			buffer_unserialize_string(buf, blen, &pos, &(*s)->name);
		else
		{
			qsnprintf(tmp, sizeof(tmp), "sub_%a", (*s)->startEA);
			sig_set_name((*s), tmp);
		}
	}
	else
	{
		pget_func_name((*s)->startEA, tmp, sizeof(tmp));
		sig_set_name(*s, tmp);
	}

	return pos;
}


/*------------------------------------------------*/
/* function : pair_serialize                      */
/* description: Serializes a signature and the    */
/*              matched signature                 */
/*------------------------------------------------*/

static size_t pair_serialize(char * buf, size_t blen, psig_t * s)
{
	size_t len;

	len = singleton_serialize(buf, blen, s, 1);
	len += singleton_serialize(buf+len, blen-len, s->msig, 2);

	return len;
}


/*------------------------------------------------*/
/* function : pair_unserialize                    */
/* description: Unserializes a signature and the  */
/*              matched signature                 */
/*------------------------------------------------*/

static size_t pair_unserialize(char * buf, size_t blen, psig_t ** s, int version)
{
	size_t len;

	len = singleton_unserialize(buf, blen, s, version);
	len += singleton_unserialize(buf+len, blen-len, &(*s)->msig, version);

	(*s)->msig->msig = (*s);

	return len;
}


/*------------------------------------------------*/
/* function : backup_save_list                    */
/* description: Backups result list inside a      */
/*              netnode                           */
/*------------------------------------------------*/

static void backup_save_list(char * node_name, slist_t * sl)
{
	char buf[5000];
	size_t i;
	size_t len;
	netnode node;

	if (!sl) return;

	node.create(node_name);

	for (i=0; i<sl->num; i++)
	{
		nodeidx_t nidx = node.altval(i);
		if (nidx != 0)
		{
			msg("backup failed: netnode already exists !!\n");
			return;
		}

		netnode n(nidx);

		n.create();
		node.altset(i, n);

		if (sl->sigs[i]->msig != NULL)
			len = pair_serialize(buf, sizeof(buf), sl->sigs[i]);
		else
			len = singleton_serialize(buf, sizeof(buf), sl->sigs[i], sl->sigs[i]->nfile);

		n.setblob(buf, len, 0, 'P');
	}
}


/*------------------------------------------------*/
/* function : backup_load_list                    */
/* description: Loads result list from a netnode  */
/*------------------------------------------------*/

static bool backup_load_list(char * node_name, slist_t * sl, int type, int version)
{
	char buf[5000];
	size_t i;
	size_t len;
	netnode node;
	nodeidx_t nidx;

	if (!sl) return true;

	node.create(node_name);

	for (i=0; i<sl->org_num; i++)
	{
		nidx = node.altval(i);
		if (nidx == BADNODE)
		{
			msg("backup failed: netnode does not exist !!\n");
			return false;
		}
		
		netnode n(nidx);

		len = sizeof(buf);
		if (!n.getblob(buf, &len, 0, 'P'))
		{
			msg("backup failed: netnode blob does not exist !!\n");
			return false;
		}

		if (type)
			pair_unserialize(buf, len, &sl->sigs[i], version);
		else
			singleton_unserialize(buf, len, &sl->sigs[i], version);
	}

	sl->num = sl->org_num;

	return true;
}


/*------------------------------------------------*/
/* function : backup_free_node                    */
/* description: Removes node from the IDB         */
/*------------------------------------------------*/

static void backup_free_node(char * node_name, size_t size)
{
	netnode node;
	size_t i;

	node.create(node_name);

	for (i=0; i<size; i++)
	{
		nodeidx_t nidx = node.altval(i);
		netnode n(nidx);
		n.delblob(0, 'P');
		n.kill();
	}

	node.kill();
}


/*------------------------------------------------*/
/* function : backup_cleanup                      */
/* description: Removes results from the IDB      */
/*------------------------------------------------*/

static void backup_cleanup(deng_t * eng)
{
	backup_free_node("$ pdiff2_matched", eng->mlist ? eng->mlist->org_num : 0);
	backup_free_node("$ pdiff2_identical", eng->ilist ? eng->ilist->org_num : 0);
	backup_free_node("$ pdiff2_unmatched", eng->ulist ? eng->ulist->org_num : 0);

	backup_free_node("$ pdiff2_eng", 1);
}


/*------------------------------------------------*/
/* function : backup_save_eng                     */
/* description:Saves engine data inside a netnode */
/*------------------------------------------------*/

static void backup_save_eng(char * node_name, deng_t * eng)
{
	char buf[1000];
	char * file;
	size_t pos = 0;
	netnode node;
	size_t msize, isize, usize;

	node.create(node_name);

	nodeidx_t nidx = node.altval(0);
	if (nidx != 0)
	{
		backup_cleanup(eng);
		node.create(node_name);

		nidx = node.altval(0);
		if (nidx != 0)
		{
			msg("backup eng failed: netnode already exists !!\n");
			return;
		}
	}

	netnode n(nidx);

	n.create();
	node.altset(0, n);

	msize = isize = usize = 0;
	if (eng->mlist)
	{
		file = eng->mlist->file;
		msize = eng->mlist->num;
	}
	if (eng->ilist)
	{
		file = eng->ilist->file;
		isize = eng->ilist->num;
	}
	if (eng->ulist)
	{
		file = eng->ulist->file;
		usize = eng->ulist->num;
	}

	buffer_serialize_int(buf, sizeof(buf), &pos, PDIFF_BACKUP_VERSION);
	buffer_serialize_string(buf, sizeof(buf), &pos, file);
	buffer_serialize_size(buf, sizeof(buf), &pos, msize);
	buffer_serialize_size(buf, sizeof(buf), &pos, isize);
	buffer_serialize_size(buf, sizeof(buf), &pos, usize);
	buffer_serialize_bool(buf, sizeof(buf), &pos, eng->opt->ipc);

	n.setblob(buf, pos, 0, 'P');
}


/*------------------------------------------------*/
/* function : backup_load_file                    */
/* description:Loads engine data inside a netnode */
/*------------------------------------------------*/

static deng_t * backup_load_eng(char * node_name, options_t * opt, int * version)
{
	char buf[1000];
	deng_t * eng;
	char * file = NULL;
	size_t blen, pos = 0;
	netnode node;
	size_t msize, isize, usize;

	node.create(node_name);

	nodeidx_t nidx = node.altval(0);
	if (nidx == 0)
		return NULL;

	netnode n(nidx);

	blen = sizeof(buf);
	n.getblob(buf, &blen, 0, 'P');
	if (!blen)
		return NULL;

	eng = (deng_t *)qalloc(sizeof(*eng));
	if (!eng)
		return NULL;

	eng->magic = 0x0BADF00D;
	eng->wnum = 0;
	eng->opt = opt;
	msize = isize = usize = 0;

	buffer_unserialize_int(buf, sizeof(buf), &pos, version);
	buffer_unserialize_string(buf, sizeof(buf), &pos, &file);
	buffer_unserialize_size(buf, sizeof(buf), &pos, &msize);
	buffer_unserialize_size(buf, sizeof(buf), &pos, &isize);
	buffer_unserialize_size(buf, sizeof(buf), &pos, &usize);
	buffer_unserialize_bool(buf, sizeof(buf), &pos, &eng->opt->ipc);

	// no need to save that in the IDB
	eng->opt->save_db = true;

	eng->mlist = siglist_init(msize, file);
	eng->ilist = siglist_init(isize, file);
	eng->ulist = siglist_init(usize, file);

	return eng;
}


/*------------------------------------------------*/
/* function : backup_save_results                 */
/* description: Saves diff results inside the     */
/*              IDB                               */
/*------------------------------------------------*/

void backup_save_results(deng_t * eng)
{
	backup_save_eng("$ pdiff2_eng", eng);

	backup_save_list("$ pdiff2_matched", eng->mlist);
	backup_save_list("$ pdiff2_identical", eng->ilist);
	backup_save_list("$ pdiff2_unmatched", eng->ulist);
}


/*------------------------------------------------*/
/* function : backup_load_results                 */
/* description: Loads diff results from the IDB   */
/*------------------------------------------------*/

int backup_load_results(deng_t ** eng, options_t * opt)
{
	int ret;
	int version;

	if (*eng)
	{
		ret = askbuttons_c("Reuse", "Refresh", "Cancel", 1,
						"Previous diff results have been found. Please specify the action to perform.");

		if (ret == 0)
		{
			diff_engine_free(*eng);
			*eng = NULL;
		}

		return ret;
	}


	*eng = backup_load_eng("$ pdiff2_eng", opt, &version);
	if (!(*eng)) return 0;

	ret = askbuttons_c("Reuse", "Refresh", "Cancel", 1,
						"Previous diff results have been found. Please specify the action to perform.");

	if (ret != 1) goto error;

	msg("Loading backup results... ");
	if (!backup_load_list("$ pdiff2_matched", (*eng)->mlist, 1, version)) goto error;
	if (!backup_load_list("$ pdiff2_identical", (*eng)->ilist, 1, version)) goto error;
	if (!backup_load_list("$ pdiff2_unmatched", (*eng)->ulist, 0, version)) goto error;
	msg("done.\n");

	return ret;

error:
	diff_engine_free(*eng);
	*eng = NULL;

	return ret;
}
