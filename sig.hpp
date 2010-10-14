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


#ifndef __SIG_H__
#define __SIG_H__

#include <ida.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <graph.hpp>

#define DIFF_UNMATCHED -1

#define CLASS_SIG 0xACDCACDC

#define SIG_PRED 1
#define SIG_SUCC 2

#define CHECK_REF 0
#define DO_NOT_CHECK_REF 1

#ifdef _WINDOWS
#define OS_CDECL __cdecl
#else
#define OS_CDECL
#endif

typedef struct signature sig_t;
typedef struct dc_sig *  pdc_sig;

struct dc_sig
{
	sig_t * sig;
	bool removed;
	pdc_sig prev;
	pdc_sig next;
};

typedef struct dc_sig dsig_t;

struct c_list
{
	size_t num;
	dsig_t * pos;   // position in sigs list
	dsig_t * sigs;  // chained list

	size_t nmatch;	// number of matched element
	dsig_t * msigs;	// matched list
};

typedef struct c_list clist_t;



typedef struct fct_ref * pfct_ref;

struct fct_ref
{
	ea_t ea;
	int type;
	char rtype;
	pfct_ref next;
};

typedef struct fct_ref fref_t;

struct fct_refs
{
	int num;
	fref_t * list;
};

typedef struct fct_refs frefs_t;

struct dline
{
	int num;
	int available;
	char * lines;
};

typedef struct dline dline_t;

typedef struct signature * psignature;

struct signature
{
	char * name;
	ea_t startEA;
	ea_t matchedEA;
	int mtype;
	psignature msig;
	int node;
	int id_crc;
	int nfile;
	int type;
	int flag;
	unsigned long sig;
	unsigned long hash;
	unsigned long hash2;
	unsigned long crc_hash;
	unsigned long str_hash;
	unsigned long lines;
	frefs_t * prefs;
	frefs_t * srefs;
	clist_t * cp;
	clist_t * cs;
	dline_t dl;
};


typedef struct sig_list * psig_list;

struct sig_list
{
	size_t num;
	size_t org_num;
	char * file;
	bool dclk;
	graph_viewer_t *gv;
	bool unique;
	psig_list msl;
	sig_t ** sigs;
};

typedef struct sig_list slist_t;


void siglist_free(slist_t *);
void siglist_partial_free(slist_t *);
int siglist_save(slist_t *, const char *);
slist_t * siglist_load(const char *);
slist_t * siglist_init(size_t, char *);
sig_t * sig_generate(size_t, qvector<ea_t> &);
sig_t * sig_class_generate(ea_t);
void clist_free(clist_t *);
void siglist_free(slist_t **);
bool siglist_realloc(slist_t *, size_t);
void siglist_add(slist_t *, sig_t *);
void siglist_remove(slist_t *, size_t);
void siglist_sort(slist_t *);
ea_t sig_get_start(sig_t * );
void sig_set_nfile(sig_t *, int);
void sig_set_matched_sig(sig_t *, sig_t *, int);
sig_t * sig_get_matched_sig(sig_t *);
void sig_set_matched_ea(sig_t *, ea_t);
ea_t sig_get_matched_ea(sig_t *);
int sig_get_matched_type(sig_t *);
frefs_t * sig_get_preds(sig_t *);
frefs_t * sig_get_succs(sig_t *);
int sig_add_pref(sig_t *, ea_t, int, char);
int sig_add_sref(sig_t *, ea_t, int, char);
clist_t * sig_get_crefs(sig_t *, int);
void sig_set_crefs(sig_t *, int, clist_t *);
int OS_CDECL sig_compare(const void *, const void *);
sig_t * sig_init();
int sig_add_block(sig_t *, short *, ea_t, ea_t, bool, char);
void sig_set_start(sig_t *, ea_t);
void sig_set_name(sig_t *, const char *);
int sig_calc_sighash(sig_t *, short *, int);
void sig_free(sig_t *);
bool sig_is_class(sig_t *);
char * pget_func_name(ea_t, char *, size_t);

#endif
