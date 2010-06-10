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


#include <pro.h>
#include <ida.hpp>
#include <xref.hpp>
#include <gdl.hpp>
#include <bytes.hpp>
#include <funcs.hpp>
#include <kernwin.hpp>
#include <fpro.h>
#include <diskio.hpp>
#include <name.hpp>
#include <ua.hpp>
#include <demangle.hpp>

#include <stdio.h>

#include "sig.hpp"
#include "x86.hpp"
#include "ppc.hpp"
#include "patchdiff.hpp"
#include "pchart.hpp"

extern cpu_t patchdiff_cpu;


/*------------------------------------------------*/
/* function : pget_func_name                      */
/* description: Gets function name                */
/*------------------------------------------------*/

char * pget_func_name(ea_t ea, char * buffer, size_t blen)
{
	char * pos;
	char tmp[512];

	if (!get_func_name(ea, buffer, blen))
		return NULL;

	// make sure this is not a c++ class/struct badly defined as a function
	demangle_name(tmp, blen, buffer, inf.long_demnames);
	if ( (strstr(tmp, "public: static") || strstr(tmp, "private: static")) &&
		(!strstr(tmp, "(") || strstr(tmp, "public: static long (__stdcall")) )
		 return NULL;

	demangle_name(buffer, blen, buffer, inf.short_demnames);

	// remove duplicates of the same name
	pos = strstr(buffer, "Z$0");
	if (pos)
		pos[0] = '\0';

	return buffer;
}


/*------------------------------------------------*/
/* function : sig_init                            */
/* description: Allocates and initializes a new   */
/*              function signature                */
/*------------------------------------------------*/

sig_t * sig_init()
{
	sig_t * sig;

	sig = (sig_t *)qalloc(sizeof(*sig));
	if (!sig)
		return NULL;

	memset(sig, 0, sizeof(*sig));

	sig->mtype = DIFF_UNMATCHED;
	sig->msig = NULL;

	return sig;
}


/*------------------------------------------------*/
/* function : frefs_free                          */
/* description: Frees chained list                */
/*------------------------------------------------*/

void frefs_free(frefs_t * frefs)
{
	fref_t * fref, * next;

	fref = frefs->list;
	while (fref)
	{
		next = fref->next;
		qfree(fref);
		fref = next;
	}

	qfree(frefs);
}


/*------------------------------------------------*/
/* function : dsig_free                           */
/* description: Frees chained list                */
/*------------------------------------------------*/

void dsig_free(dsig_t * ds)
{
	dsig_t * next;

	while (ds)
	{
		next = ds->next;
		qfree(ds);
		ds = next;
	}

	qfree(ds);
}


/*------------------------------------------------*/
/* function : clist_free                          */
/* description: Frees clist_t structure           */
/*------------------------------------------------*/

void clist_free(clist_t * cl)
{
	dsig_free(cl->sigs);
	dsig_free(cl->msigs);

	qfree(cl);
}


/*------------------------------------------------*/
/* function : sig_free                            */
/* description: Frees signature                   */
/*------------------------------------------------*/

void sig_free(sig_t * sig)
{
	if (sig->name)
	{
		qfree(sig->name);
		sig->name = NULL;
	}

	if (sig->dl.lines != NULL)
		qfree(sig->dl.lines);


	if (sig->prefs) frefs_free(sig->prefs);
	if (sig->srefs) frefs_free(sig->srefs);
	if (sig->cp) clist_free(sig->cp);
	if (sig->cs) clist_free(sig->cs);

	qfree(sig);
}


/*------------------------------------------------*/
/* function : sig_set_name                        */
/* description: Sets function signature name      */
/*------------------------------------------------*/

void sig_set_name(sig_t * sig, const char * name)
{
	sig->name = qstrdup(name);
}


/*------------------------------------------------*/
/* function : sig_set_start                       */
/* description: Sets function start address       */
/*------------------------------------------------*/

void sig_set_start(sig_t * sig, ea_t ea)
{
	sig->startEA = ea;
}


/*------------------------------------------------*/
/* function : sig_get_start                       */
/* description: Returns function start address    */
/*------------------------------------------------*/

ea_t sig_get_start(sig_t * sig)
{
	return sig->startEA;
}


/*------------------------------------------------*/
/* function : sig_get_preds                       */
/* description: Returns signature pred xrefs      */
/*------------------------------------------------*/

frefs_t * sig_get_preds(sig_t * sig)
{
	return sig->prefs;
}


/*------------------------------------------------*/
/* function : sig_get_succs                       */
/* description: Returns signature succ xrefs      */
/*------------------------------------------------*/

frefs_t * sig_get_succs(sig_t * sig)
{
	return sig->srefs;
}


/*------------------------------------------------*/
/* function : sig_get_crefs                       */
/* description: Returns signature cxrefs          */
/*------------------------------------------------*/

clist_t * sig_get_crefs(sig_t * sig, int type)
{
	if (type == SIG_PRED)
		return sig->cp;
	
	if (type == SIG_SUCC)
		return sig->cs;

	return NULL;
}


/*------------------------------------------------*/
/* function : sig_set_crefs                       */
/* description: Sets signature cxrefs             */
/*------------------------------------------------*/

void sig_set_crefs(sig_t * sig, int type, clist_t * cl)
{
	if (type == SIG_PRED)
		sig->cp = cl;
	
	else if (type == SIG_SUCC)
		sig->cs = cl;
}


/*------------------------------------------------*/
/* function : sig_set_nfile                       */
/* description: Sets file number                  */
/*------------------------------------------------*/

void sig_set_nfile(sig_t * sig, int num)
{
	sig->nfile = num;
}


/*------------------------------------------------*/
/* function : sig_set_matched_sig                 */
/* description: Sets matched address              */
/*------------------------------------------------*/

void sig_set_matched_sig(sig_t * sig, sig_t * sig2, int type)
{
	sig->msig = sig2;
	sig->matchedEA = sig2->startEA;

	sig2->msig = sig;
	sig2->matchedEA = sig->startEA;

	sig->mtype = sig2->mtype = type;

	if (sig->crc_hash != sig2->crc_hash)
		sig->id_crc = sig2->id_crc = 1;
}


/*------------------------------------------------*/
/* function : sig_get_matched_sig                 */
/* description: Returns matched address           */
/*------------------------------------------------*/

sig_t * sig_get_matched_sig(sig_t * sig)
{
	return sig->msig;
}


/*------------------------------------------------*/
/* function : sig_get_matched_type                */
/* description: Returns matched type              */
/*------------------------------------------------*/

int sig_get_matched_type(sig_t * sig)
{
	return sig->mtype;
}


/*------------------------------------------------*/
/* function : sig_add_fref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_add_fref(frefs_t ** frefs, ea_t ea, int type, char rtype)
{
	fref_t * ref, * next;

	if (!*frefs)
	{
		*frefs = (frefs_t *)qalloc(sizeof(**frefs));
		if (!*frefs) return -1;

		memset(*frefs, 0, sizeof(**frefs));
	}
	else
	{
		//don't add duplicates
		next = (*frefs)->list;
		while(next)
		{
			if (next->ea == ea)
				return -1;

			next = next->next;
		}
	}

	ref = (fref_t *)qalloc(sizeof(*ref));
	if (!ref) return -1;

	ref->ea = ea;
	ref->type = type;
	ref->rtype = rtype;
	ref->next = (*frefs)->list;

	(*frefs)->num++;
	(*frefs)->list = ref;

	return 0;
}


/*------------------------------------------------*/
/* function : sig_add_pref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_add_pref(sig_t * sig, ea_t ea, int type, char rtype)
{
	return sig_add_fref(&sig->prefs, ea, type, rtype);
}


/*------------------------------------------------*/
/* function : sig_add_sref                        */
/* description: Adds a function reference to the  */
/*              signature                         */
/*------------------------------------------------*/

int sig_add_sref(sig_t * sig, ea_t ea, int type, char rtype)
{
	return sig_add_fref(&sig->srefs, ea, type, rtype);
}


/*------------------------------------------------*/
/* function : is_fake_jump                        */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump                      */
/*------------------------------------------------*/

bool is_fake_jump(ea_t ea)
{
	switch(patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		if (x86_get_fake_jump(ea) != BADADDR)
			return true;
	default:
		return false;
	}
}

/*------------------------------------------------*/
/* function : ignore_jump                         */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump that must be ignored */
/*              in the signature                  */
/*------------------------------------------------*/

bool ignore_jump(ea_t ea)
{
	switch(patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		if (!x86_is_direct_jump(ea))
			return false;
	default:
		return true;
	}
}


/*------------------------------------------------*/
/* function : is_jump                             */
/* description: Returns TRUE if the instruction at*/
/*              ea is a jump                      */
/*------------------------------------------------*/

bool is_jump(sig_t * sig, ea_t ea, bool * call, bool * cj)
{
	xrefblk_t xb;
	cref_t cr;

	*call = false;
	*cj = false;

	if (xb.first_from(ea, XREF_FAR))
	{
		cr = (cref_t)xb.type;
		if (xb.iscode && (cr == fl_JF || cr == fl_JN))
			if (ignore_jump(ea))
				return true;
			else
				*cj = true;

		if (xb.iscode && (cr == fl_CF || cr == fl_CN))
		{
			if (sig->type == 1)
				sig_add_sref(sig, xb.to, 0, CHECK_REF);

			*call = true;
		}
	}
	else
		return is_fake_jump(ea);

	return false;
}


/*------------------------------------------------*/
/* function : remove_instr                        */
/* description: Returns TRUE if the instruction at*/
/*              ea must not be added to the sig   */
/*------------------------------------------------*/

bool remove_instr(unsigned char byte, ea_t ea)
{
	switch (patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		return x86_remove_instr(byte, ea);
	case CPU_PPC:
		return ppc_remove_instr(byte, ea);
	default:
		return false;
	}
}


/*------------------------------------------------*/
/* function : get_byte_with_optimization          */
/* description: Returns byte at address ea        */
/* note: Uses the processor optimized function if */
/*       available                                */
/*------------------------------------------------*/

char get_byte_with_optimization(ea_t ea)
{
	switch (patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		return x86_get_byte(ea);
	case CPU_PPC:
		return ppc_get_byte(ea);
	default:
		{
			ua_ana0(ea);
			return (char)cmd.itype;
		}
	}
}


unsigned long ror(unsigned long val, int r)
{
	return (val >> r) | (val << (32-r));
}


/*------------------------------------------------*/
/* function : dline_add                           */
/* description: Adds a disassembled line to the   */
/*              signature                         */
/*------------------------------------------------*/

int dline_add(dline_t * dl, ea_t ea, char options)
{
	char buf[256];
	char tmp[256];
	char dis[256];
	char addr[30];
	char * dll;
	int len;
	flags_t f;

	buf[0] = '\0';

	f = getFlags(ea);
	generate_disasm_line(ea, dis, sizeof(dis));

	ua_ana0(ea);
	init_output_buffer(buf, sizeof(buf));

	// Adds block label
	if (has_dummy_name(f))
	{
		get_nice_colored_name(ea,tmp,sizeof(tmp),GNCN_NOSEG|GNCN_NOFUNC);
		out_snprintf("%s", tmp);
		out_line(":\n", COLOR_DATNAME);
	}

	if (options)
	{
		qsnprintf(addr, sizeof(addr), "%a", ea);
		out_snprintf("%s ", addr);
	}

	out_insert(get_output_ptr(), dis);
	term_output_buffer();

	len = strlen(buf);

	if (dl->available < (len+3))
	{
		dll = (char *)qrealloc(dl->lines, sizeof(char*) * (dl->num+len+256));
		if (!dll) return -1;

		dl->available = len+256;
		dl->lines = dll;
	}

	if (dl->num)
	{
		dl->lines[dl->num] = '\n';
		dl->num++;
	}

	memcpy(&dl->lines[dl->num], buf, len);

	dl->available -= len+1;
	dl->num += len;

	dl->lines[dl->num] = '\0';

	return 0;
}


/*------------------------------------------------*/
/* function : sig_add_address                     */
/* description: Adds an address to the signature  */
/*------------------------------------------------*/

int sig_add_address(sig_t * sig, short opcodes[256], ea_t ea, bool b, bool line, char options)
{
	unsigned char byte;
	unsigned char buf[200];
	size_t s, i;
	bool call;
	bool cj;
	ea_t tea;
	flags_t f;

	if (line)
		dline_add(&sig->dl, ea, options);

	if (is_jump(sig, ea, &call, &cj))
		return -1;

	byte = get_byte_with_optimization(ea);

	if (remove_instr(byte, ea))
		return -1;

	sig->lines++;
	opcodes[byte]++;

	if (!b && !call)
	{
		if (cj)
		{
			buf[0] = byte;
			s = 1;
		}
		else
		{
			s = get_item_size(ea);
			if (s > sizeof(buf)) s = sizeof(buf);
			get_many_bytes(ea, buf, s);
		}

		for (i=0; i<s; i++)
		{
			sig->crc_hash += buf[i];
			sig->crc_hash += ( sig->crc_hash << 10 );
			sig->crc_hash ^= ( sig->crc_hash >> 6 );
		}
	}
	else if (b)
	{
		tea = get_first_dref_from(ea);
		if (tea != BADADDR)
		{
			f = getFlags(tea);
			if (isASCII(f))
			{
				long strtype;

				get_typeinfo(tea, 0, f, (typeinfo_t *)&strtype);
				s = get_max_ascii_length(tea, strtype);
				if (!get_ascii_contents(tea, s, strtype, (char *)buf, sizeof(buf)))
					s = sizeof(buf);

				for (i=0; i<s; i++)
					sig->str_hash += buf[i]*i;
			}
		}
	}

	return 0;
}


/*------------------------------------------------*/
/* function : sig_add_block                       */
/* description: Adds a block to the signature     */
/*------------------------------------------------*/

int sig_add_block(sig_t * sig, short opcodes[256], ea_t startEA, ea_t endEA, bool line, char options)
{
	ea_t ea;
	flags_t flags;
	bool b;

	ea = startEA;
	while (ea < endEA)
	{
		flags = getFlags (ea);
		if (!isCode (flags))
			return -1;

		b = get_first_dref_from(ea) != BADADDR ? true : false;
		sig_add_address(sig, opcodes, ea, isOff(flags, OPND_ALL) || b, line, options);

		ea += get_item_size(ea);
	}

	return 0;
}


int __cdecl compare(const void *arg1, const void *arg2)
{
   return *((short *)arg1) - *((short *)arg2);
}


/*------------------------------------------------*/
/* function : sig_calc_sighash                    */
/* description: generates a sig/hash for the      */
/*              signature opcodes                 */
/*------------------------------------------------*/

int sig_calc_sighash(sig_t * sig, short _opcodes[256], int do_sig)
{
	short tmp;
	short opcodes[256];
	int i, j;

	memcpy(opcodes, _opcodes, sizeof(opcodes));
	qsort(opcodes, 256, sizeof(short), compare);

	for (i=0; i<256; i++)
		for (j=0; j<255; j++)
			if (opcodes[j] > opcodes[j+1])
			{
				tmp = opcodes[j+1];
				opcodes[j+1] = opcodes[j];
				opcodes[j] = tmp;
			}

	sig->hash2 = 0;
	if (do_sig)	sig->sig = 0;

	for (i=0; i<256; i++)
	{
		if (do_sig) sig->sig += opcodes[i] * i;
		sig->hash2 = ror(sig->hash2, 13);
		sig->hash2 += _opcodes[i];
	}

	return 0;
}


/*------------------------------------------------*/
/* function : sig_parse_dref_list                 */
/* description: checks if the data ref is a class */
/*              like structure. Returns class ea  */
/*              on success                        */
/*------------------------------------------------*/

ea_t sig_parse_dref_list(sig_t * sig, ea_t ea)
{
	ea_t fref;
	flags_t f;

	// scan up
	do
	{
		fref = get_first_dref_from(ea);
		if (fref == BADADDR)
			return BADADDR;

		f = getFlags(fref);
		if (!isCode(f))
			return BADADDR;

		fref = get_first_dref_to(ea);
		if (fref != BADADDR)
		{
			f = getFlags(fref);
			if (!isCode(f))
				return BADADDR;

			return ea;
		}

		ea = prev_visea(ea);
	} while(ea != BADADDR);

	return ea;
}


/*------------------------------------------------*/
/* function : sig_is_class                        */
/* description: Returns true is the signature is  */
/*              a class                           */
/*------------------------------------------------*/

bool sig_is_class(sig_t * sig)
{
	if (sig->sig == CLASS_SIG && sig->hash == CLASS_SIG && sig->crc_hash == CLASS_SIG)
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : sig_class_generate                  */
/* description: generates a signature for the     */
/*              class structure                   */
/*------------------------------------------------*/

sig_t * sig_class_generate(ea_t ea)
{
	func_t * xfct;
	sig_t * sig;
	ea_t fref;
	char buf[512];

	sig = sig_init();
	if (!sig)
		return NULL;

	// Adds function start address
	sig_set_start(sig, ea);

	// Adds function name
	qsnprintf(buf, sizeof(buf), "sub_%a", ea);
	sig_set_name(sig, buf);

	// Adds class references
	fref = get_first_dref_to(ea);
	while (fref != BADADDR)
	{
		xfct = get_func(fref);
		if (xfct)
			sig_add_sref(sig, xfct->startEA, 0, CHECK_REF);

		fref = get_next_dref_to(ea, fref);
	}

	sig->hash = sig->crc_hash = sig->sig = CLASS_SIG;

	return sig;
}


/*------------------------------------------------*/
/* function : sig_generate                        */
/* description: generates a signature for the     */
/*              given function                    */
/*------------------------------------------------*/

sig_t * sig_generate(size_t fct_num, qvector<ea_t> & class_l)
{
	func_t * fct, * xfct;
	pflow_chart_t * fchart;
	sig_t * sig;
	ea_t fref, ea;
	int bnum, i;
	char buf[512];
	short opcodes[256];
	qvector<int> call_list;
	flags_t f;

	fct = getn_func(fct_num);

	memset(opcodes, '\0', sizeof(opcodes));
	fchart = new pflow_chart_t(fct);
	sig = sig_init();
	if (!sig)
	{
		delete fchart;
		return NULL;
	}

	sig->type = 1;

	// Adds function start address
	sig_set_start(sig, fct->startEA);

	// Adds function name
	if (pget_func_name(fct->startEA, buf, sizeof(buf)))
		sig_set_name(sig, buf);
	else return NULL;

	// Adds function references

	fref = get_first_dref_to(fct->startEA);

	while (fref != BADADDR)
	{
		f = getFlags(fref);
		if (isCode(f))
		{
			xfct = get_func(fref);
			if (xfct && xfct->startEA != fct->startEA)
				sig_add_pref(sig, xfct->startEA, 0, CHECK_REF);
		}
		else
		{
			ea = sig_parse_dref_list(sig, fref);
			if (ea != BADADDR)
			{
				sig_add_pref(sig, ea, 0, CHECK_REF);
				class_l.add_unique(ea);
			}
		}

		fref = get_next_dref_to(fct->startEA, fref);
	}


	// Adds each block to the signature
	bnum = fchart->nproper;
	
	sig->hash = 0;
	sig->sig = 0;


	for (i=0; i<bnum; i++)
	{
		int j;
		int ttype;
		int smax = fchart->nsucc(i);
		sig->sig += (i+1) + smax*i;

		sig_add_block(sig, opcodes, fchart->blocks[i].startEA, fchart->blocks[i].endEA, 0, 0);
		for(j=0; j<smax; j++)
		{
			sig->hash = ror(sig->hash, 13);
			ttype = fchart->blocks[i].succ[j].type;
			if (ttype == 2) ttype--;
			sig->hash += ttype;
		}
	}

	sig_calc_sighash(sig, opcodes, 0);

	delete fchart;

	return sig;
}


/*------------------------------------------------*/
/* function : sig_save                            */
/* description: Saves signature refs to disk	  */
/*------------------------------------------------*/

void sig_save_refs(FILE * fp, frefs_t * refs)
{
	int num, i;
	fref_t * tmp;

	if (refs)
	{
		num = refs->num;
		qfwrite(fp, &num, sizeof(num));
		tmp = refs->list;
		for (i=0; i<num; i++)
		{
			qfwrite(fp, &tmp->ea, sizeof(tmp->ea));
			qfwrite(fp, &tmp->type, sizeof(tmp->type));
			tmp = tmp->next;
		}
	}
	else
	{
		num = 0;
		qfwrite(fp, &num, sizeof(num));
	}
}


/*------------------------------------------------*/
/* function : sig_save                            */
/* description: Saves signature to disk	          */
/*------------------------------------------------*/

int sig_save(sig_t * sig, FILE * fp)
{
	size_t len;

	// saves function name
	len = strlen(sig->name);
	qfwrite(fp, &len, sizeof(len));
	qfwrite(fp, sig->name, len);

	// saves function start address
	qfwrite(fp, &sig->startEA, sizeof(sig->startEA));

	// saves function lines
	qfwrite(fp, &sig->dl.num, sizeof(sig->dl.num));
	qfwrite(fp, sig->dl.lines, sig->dl.num);

	// saves sig/hash
	qfwrite(fp, &sig->sig, sizeof(sig->sig));
	qfwrite(fp, &sig->hash, sizeof(sig->hash));
	qfwrite(fp, &sig->hash2, sizeof(sig->hash2));
	qfwrite(fp, &sig->crc_hash, sizeof(sig->crc_hash));
	qfwrite(fp, &sig->str_hash, sizeof(sig->str_hash));

	// saves function refs
	sig_save_refs(fp, sig->prefs);
	sig_save_refs(fp, sig->srefs);

	return 0;
}


/*------------------------------------------------*/
/* function : sig_load_prefs                      */
/* description: Loads signature  refs from disk   */
/*------------------------------------------------*/

void sig_load_prefs(sig_t * sig, FILE * fp, int type)
{
	int num, i;
	pedge_t * eatab;

	// loads function refs in reverse order
	qfread(fp, &num, sizeof(num));
	eatab = (pedge_t *)qalloc(num * sizeof(*eatab));

	for (i=0; i<num; i++)
	{
		qfread(fp, &eatab[i].ea, sizeof(eatab[i].ea));
		qfread(fp, &eatab[i].type, sizeof(eatab[i].type));
	}

	for (i=num; i>0; i--)
	{
		if (type == SIG_PRED)
			sig_add_pref(sig, eatab[i-1].ea, eatab[i-1].type, CHECK_REF);
		else
			sig_add_sref(sig, eatab[i-1].ea, eatab[i-1].type, CHECK_REF);
	}

	qfree(eatab);
}


/*------------------------------------------------*/
/* function : sig_load                            */
/* description: Loads signature from disk         */
/*------------------------------------------------*/

sig_t * sig_load(FILE * fp)
{
	size_t len;
	sig_t * sig;
	char buf[512];

	sig = sig_init();
	if (!sig) return NULL;

	// loads function name
	qfread(fp, &len, sizeof(len));
	qfread(fp, buf, len);
	buf[len] = '\0';

	sig_set_name(sig, buf);

	// loads function start address
	qfread(fp, &sig->startEA, sizeof(sig->startEA));

	// loads function line
	qfread(fp, &sig->dl.num, sizeof(sig->dl.num));
	sig->dl.lines = (char *)qalloc((sig->dl.num+1) * sizeof(char));
	if (sig->dl.lines)
	{
		qfread(fp, sig->dl.lines, sig->dl.num);
		sig->dl.lines[sig->dl.num] = '\0';
	}
	else
		sig->dl.num = 0;


	// loads sig/hash
	qfread(fp, &sig->sig, sizeof(sig->sig));
	qfread(fp, &sig->hash, sizeof(sig->hash));
	qfread(fp, &sig->hash2, sizeof(sig->hash2));
	qfread(fp, &sig->crc_hash, sizeof(sig->crc_hash));
	qfread(fp, &sig->str_hash, sizeof(sig->str_hash));

	// loads sig refs
	sig_load_prefs(sig, fp, SIG_PRED);
	sig_load_prefs(sig, fp, SIG_SUCC);

	return sig;
}


/*------------------------------------------------*/
/* function : siglist_init                        */
/* description: Initializes a new signature list  */
/*------------------------------------------------*/

slist_t * siglist_init(size_t num, char * file)
{
	slist_t * l;

	l = (slist_t *)qalloc(sizeof(*l));
	if (!l)	return NULL;

	l->file = file;
	l->num = 0;
	l->org_num = num;
	l->sigs = (sig_t **)qalloc(num * sizeof(*l->sigs));

	if (!l->sigs && l->org_num != 0)
	{
		qfree(l);
		return NULL;
	}

	return l;
}


/*------------------------------------------------*/
/* function : siglist_realloc                     */
/* description: Realloc a signature list          */
/*------------------------------------------------*/

bool siglist_realloc(slist_t * sl, size_t num)
{
	sig_t ** sigs;

	sigs = (sig_t **)qrealloc(sl->sigs, (sl->org_num + num) * sizeof(*sl->sigs));
	if (!sigs)
		return false;

	sl->org_num += num;
	sl->sigs = sigs;

	return true;
}


/*------------------------------------------------*/
/* function : sig_compare                         */
/* description: Compares two signature            */
/*------------------------------------------------*/

int __cdecl sig_compare(const void *arg1, const void *arg2)
{
	unsigned long v1, v2;

	v1 = (*(sig_t **)arg1)->sig;
	v2 = (*(sig_t **)arg2)->sig;

	if (v2 > v1) return 1;
	if (v2 < v1) return -1;

	v1 = (*(sig_t **)arg1)->hash;
	v2 = (*(sig_t **)arg2)->hash;

	if (v2 > v1) return 1;
	if (v2 < v1) return -1;

	v1 = (*(sig_t **)arg1)->crc_hash;
	v2 = (*(sig_t **)arg2)->crc_hash;

	if (v2 > v1) return 1;
	if (v2 < v1) return -1;

	v1 = (*(sig_t **)arg1)->str_hash;
	v2 = (*(sig_t **)arg2)->str_hash;

	if (v2 > v1) return 1;
	if (v2 < v1) return -1;

	return 0;
}


/*------------------------------------------------*/
/* function : siglist_sort                        */
/* description: Sorts the signature to the list   */
/*------------------------------------------------*/

void siglist_sort(slist_t * sl)
{
	qsort(sl->sigs, sl->num, sizeof(*sl->sigs), sig_compare);
}


/*------------------------------------------------*/
/* function : siglist_add                         */
/* description: Adds a new signature to the list  */
/*------------------------------------------------*/

void siglist_add(slist_t * sl, sig_t * sig)
{
	if (sl->num >= sl->org_num)
	{
		if (!siglist_realloc(sl, 32))
			return;
	}

	sig->node = sl->num;
	sl->sigs[sl->num++] = sig;
}


/*------------------------------------------------*/
/* function : siglist_remove                      */
/* description: Removes a new signature to the    */
/*              list                              */
/*------------------------------------------------*/

void siglist_remove(slist_t * sl, size_t n)
{
	if ( (n+1) < sl->num )
		memmove(&sl->sigs[n], &sl->sigs[n+1], ((sl->num - 1) - n) * sizeof(*(sl->sigs)));

	sl->num--;
}


/*------------------------------------------------*/
/* function : siglist_free                        */
/* description: Frees a new signature list        */
/*------------------------------------------------*/

void siglist_free(slist_t * sl)
{
	size_t i;

	for (i=0; i<sl->num; i++)
		sig_free(sl->sigs[i]);

	qfree(sl->sigs);
	qfree(sl);
}


/*------------------------------------------------*/
/* function : siglist_partial_free                */
/* description: Frees a new signature list        */
/*------------------------------------------------*/

void siglist_partial_free(slist_t * sl)
{
	qfree(sl->sigs);
	qfree(sl);
}


/*------------------------------------------------*/
/* function : siglist_getnum                      */
/* description: Returns number of signature in    */
/*              list                              */
/*------------------------------------------------*/

size_t siglist_getnum(slist_t * sl)
{
	return sl->num;
}


/*------------------------------------------------*/
/* function : siglist_save                        */
/* description: Saves signature list to disk      */
/*------------------------------------------------*/

int siglist_save(slist_t * sl, const char * filename)
{
	FILE * fp;
	size_t num, i;

	fp = qfopen(filename, "wb+");
	if (fp == 0) return -1;

	num = siglist_getnum(sl);
	qfwrite(fp, &num, sizeof(num));

	for (i=0; i<num; i++)
		sig_save(sl->sigs[i], fp);

	qfclose(fp);

	return 0;
}


/*------------------------------------------------*/
/* function : siglist_load                        */
/* description: Loads signature list from disk    */
/*------------------------------------------------*/

slist_t * siglist_load(const char * filename)
{
	FILE * fp;
	slist_t * sl;
	sig_t * sig;
	size_t num, i;

	fp = qfopen(filename, "rb");
	if (fp < 0) return NULL;

	if (qfread(fp, &num, sizeof(num)) != sizeof(num))
	{
		qfclose(fp);
		return NULL;
	}

	sl = siglist_init(num, NULL);
	if (!sl)
	{
		qfclose(fp);
		return NULL;
	}

	for (i=0; i<num; i++)
	{
		sig = sig_load(fp);
		siglist_add(sl, sig);
	}

	siglist_sort(sl);

	qfclose(fp);

	return sl;
}

