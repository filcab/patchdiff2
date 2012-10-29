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

#include "diff.hpp"
#include "display.hpp"
#include "os.hpp"
#include "parser.hpp"
#include "pgraph.hpp"
#include "options.hpp"
#include "system.hpp"


static uint32 idaapi sizer_dlist(slist_t * sl)
{
	if (sl)
		return sl->num;

	return 0;
}

static uint32 idaapi sizer_match(void *obj)
{
	deng_t * d = (deng_t *)obj;

	return sizer_dlist(d ? d->mlist : NULL);
}


static uint32 idaapi sizer_identical(void *obj)
{
	deng_t * d = (deng_t *)obj;

	return sizer_dlist(d ? d->ilist : NULL);
}


static uint32 idaapi sizer_unmatch(void *obj)
{
	if (obj)
		return ((deng_t *)obj)->ulist->num;

	return 0;
}

static void idaapi close(void *obj)
{
	deng_t * d = (deng_t *)obj;

	d->wnum--;
	if (!d->wnum)
		ipc_close();

	return;
}


static void idaapi desc_dlist(slist_t * sl,uint32 n,char * const *arrptr)
{
	int i;

	/* header */
	if (n == 0)
	{
		for (i = 0; i < qnumber (header_match); i++)
			qsnprintf(arrptr[i], MAXSTR, "%s", header_match[i]);
	}
	else
	{
		qsnprintf(arrptr[0], MAXSTR, "%u", sl->sigs[n-1]->mtype);
		qsnprintf(arrptr[1], MAXSTR, "%s", sl->sigs[n-1]->name);
		qsnprintf(arrptr[2], MAXSTR, "%s", sl->sigs[n-1]->msig->name);
		qsnprintf(arrptr[3], MAXSTR, "%a", sl->sigs[n-1]->startEA);
		qsnprintf(arrptr[4], MAXSTR, "%a", sl->sigs[n-1]->msig->startEA);
		qsnprintf(arrptr[5], MAXSTR, "%c", sl->sigs[n-1]->id_crc ? '+' : '-');
		qsnprintf(arrptr[6], MAXSTR, "%a", sl->sigs[n-1]->crc_hash);
		qsnprintf(arrptr[7], MAXSTR, "%a", sl->sigs[n-1]->msig->crc_hash);
	}
}


/*------------------------------------------------*/
/* function : desc_match                          */
/* description: Fills matched list                */
/*------------------------------------------------*/

static void idaapi desc_match(void *obj,uint32 n,char * const *arrptr)
{
	deng_t * d = (deng_t *)obj;

	desc_dlist(d ? d->mlist : NULL, n, arrptr);
}


/*------------------------------------------------*/
/* function : desc_identical                      */
/* description: Fills identical list              */
/*------------------------------------------------*/

static void idaapi desc_identical(void *obj,uint32 n,char * const *arrptr)
{
	deng_t * d = (deng_t *)obj;

	desc_dlist(d ? d->ilist : NULL, n, arrptr);
}


/*------------------------------------------------*/
/* function : desc_unmatch                        */
/* description: Fills unmatched list              */
/*------------------------------------------------*/

static void idaapi desc_unmatch(void *obj,uint32 n,char * const *arrptr)
{
	int i;
	slist_t * sl;

	/* header */
	if (n == 0)
	{
		for (i = 0; i < qnumber (header_unmatch); i++)
			qsnprintf(arrptr[i], MAXSTR, "%s", header_unmatch[i]);
	}
	else
	{
		sl = ((deng_t *)obj)->ulist;

		qsnprintf(arrptr[0], MAXSTR, "%u", sl->sigs[n-1]->nfile);
		qsnprintf(arrptr[1], MAXSTR, "%s", sl->sigs[n-1]->name);
		qsnprintf(arrptr[2], MAXSTR, "%a", sl->sigs[n-1]->startEA);
		qsnprintf(arrptr[3], MAXSTR, "%.8X", sl->sigs[n-1]->sig);
		qsnprintf(arrptr[4], MAXSTR, "%.8X", sl->sigs[n-1]->hash);
		qsnprintf(arrptr[5], MAXSTR, "%.8X", sl->sigs[n-1]->crc_hash);
	}
}


static void idaapi enter_list(slist_t * sl,uint32 n)
{
	jumpto(sl->sigs[n-1]->startEA);
	os_copy_to_clipboard(NULL);
}


/*------------------------------------------------*/
/* function : enter_match                         */
/* description: Jumps to code for element n in    */
/*              matched list                      */
/*------------------------------------------------*/

static void idaapi enter_match(void *obj,uint32 n)
{
	enter_list(((deng_t *)obj)->mlist, n);
}


/*------------------------------------------------*/
/* function : enter_match                         */
/* description: Jumps to code for element n in    */
/*              identical list                    */
/*------------------------------------------------*/

static void idaapi enter_identical(void *obj,uint32 n)
{
	enter_list(((deng_t *)obj)->ilist, n);
}


/*------------------------------------------------*/
/* function : enter_match                         */
/* description: Jumps to code for element n in    */
/*              unmatched list                    */
/*------------------------------------------------*/

static void idaapi enter_unmatch(void *obj,uint32 n)
{
	slist_t * sl = ((deng_t *)obj)->ulist;

	if (sl->sigs[n-1]->nfile == 1)
		jumpto(sl->sigs[n-1]->startEA);
	else
		os_copy_to_clipboard(NULL);
}


static uint32 idaapi graph_list(slist_t * sl,uint32 n, options_t * opt)
{
	slist_t * sl1 = NULL;
	slist_t * sl2 = NULL;

	msg ("parsing second function...\n");
	sl2 = parse_second_fct(sl->sigs[n-1]->msig->startEA, sl->file, opt);
	if (!sl2)
	{
		msg("Error: FCT2 parsing failed.\n");
		return 0;
	}

	msg ("parsing first function...\n");
	sl1 = parse_fct(sl->sigs[n-1]->startEA, dto.graph.s_showpref);
	if (!sl1)
	{
		msg("Error: FCT1 parsing failed.\n");
		siglist_free(sl2);
		return 0;
	}

	sl1->sigs[0]->nfile = 1;
	sl2->sigs[0]->nfile = 2;

	msg ("diffing functions...\n");
	generate_diff(NULL, sl1, sl2, NULL, false, NULL);

	pgraph_display(sl1, sl2);

	msg ("done!\n");
	return 1;
}


/*------------------------------------------------*/
/* function : graph_match                         */
/* description: Draws graph from element n in     */
/*              matched list                      */
/*------------------------------------------------*/

static void idaapi graph_match(void *obj,uint32 n)
{
	slist_t * sl = ((deng_t *)obj)->mlist;
	options_t * opt = ((deng_t *)obj)->opt;

	graph_list(sl, n, opt);

	return;
}


/*------------------------------------------------*/
/* function : graph_identical                     */
/* description: Draws graph from element n in     */
/*              identical list                    */
/*------------------------------------------------*/

static void idaapi graph_identical(void *obj,uint32 n)
{
	slist_t * sl = ((deng_t *)obj)->ilist;
	options_t * opt = ((deng_t *)obj)->opt;

	graph_list(sl, n, opt);

	return;
}


/*------------------------------------------------*/
/* function : graph_unmatch                       */
/* description: Draws graph from element n in     */
/*              unmatched list                    */
/*------------------------------------------------*/

static void idaapi graph_unmatch(void *obj,uint32 n)
{
	slist_t * sl = NULL, * tmp = ((deng_t *)obj)->ulist;

	if (tmp->sigs[n-1]->nfile == 2)
	{
		msg ("parsing second function...\n");
		sl = parse_second_fct(tmp->sigs[n-1]->startEA, tmp->file, ((deng_t *)obj)->opt);
		if (!sl)
		{
			msg("Error: FCT2 parsing failed.\n");
			return;
		}

		sl->sigs[0]->nfile = 2;
	}
	else
	{
		msg ("parsing first function...\n");
		sl = parse_fct(tmp->sigs[n-1]->startEA, dto.graph.s_showpref);
		if (!sl)
		{
			msg("Error: FCT1 parsing failed.\n");
			return;
		}

		sl->sigs[0]->nfile = 1;
	}

	pgraph_display_one(sl);

	msg ("done!\n");
	return;
}


static uint32 idaapi res_unmatch(deng_t * d,uint32 n, int type)
{
	slist_t * sl;

	if (type == 0)
		sl = d->ilist;
	else
		sl = d->mlist;
	
	sl->sigs[n-1]->nfile = 1;
	sl->sigs[n-1]->msig->nfile = 2;

	siglist_add(d->ulist, sl->sigs[n-1]);
	siglist_add(d->ulist, sl->sigs[n-1]->msig);

	sl->sigs[n-1]->msig->msig = NULL;
	sl->sigs[n-1]->msig = NULL;

	siglist_remove(sl, n-1);

	refresh_chooser(title_unmatch);

	return 1;
}


/*------------------------------------------------*/
/* function : res_iunmatch                        */
/* description: Unmatches element n from identical*/
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_iunmatch(void *obj,uint32 n)
{
	return res_unmatch((deng_t *)obj, n, 0);
}


/*------------------------------------------------*/
/* function : res_munmatch                        */
/* description: Unmatches element n from matched  */
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_munmatch(void *obj,uint32 n)
{
	return res_unmatch((deng_t *)obj, n, 1);
}


/*------------------------------------------------*/
/* function : propagate_match                     */
/* description: Propagates new matched result if  */
/*              option is set in dialog box       */
/*------------------------------------------------*/

void propagate_match(deng_t * eng, psig_t * s1, psig_t * s2, int options)
{
	size_t i;
	deng_t * d = NULL;
	slist_t * l1, * l2;

	if (options)
	{
		show_wait_box ("PatchDiff is in progress ...");

		l1 = siglist_init(eng->ulist->num, eng->ulist->file);
		l2 = siglist_init(eng->ulist->num, eng->ulist->file);

		for (i=0; i<eng->ulist->num; i++)
			if (!eng->ulist->sigs[i]->msig)
			{
				if (eng->ulist->sigs[i]->nfile == 1)
					siglist_add(l1, eng->ulist->sigs[i]);
				else
					siglist_add(l2, eng->ulist->sigs[i]);
			}

		generate_diff(&d, l1, l2, eng->ulist->file, false, NULL);

		siglist_partial_free(l1);
		siglist_partial_free(l2);

		hide_wait_box();
	}

	i = 0;
	while (i<eng->ulist->num)
	{
		s1 = eng->ulist->sigs[i];
		s2 = s1->msig;

		if (!s2) 
			i++;
		else
		{
			if (s1->nfile == 1)
			{
				if (sig_equal(s1, s2, DIFF_EQUAL_SIG_HASH))
					siglist_add(eng->ilist, s1);
				else
					siglist_add(eng->mlist, s1);
			}

			siglist_remove(eng->ulist, i);
		}
	}
}


/*------------------------------------------------*/
/* function : res_match                           */
/* description: Matches 2 elements from unmatched */
/*              list                              */
/*------------------------------------------------*/

static uint32 idaapi res_match(void *obj,uint32 n)
{
	deng_t * eng = (deng_t *)obj;
	psig_t * s1, * s2;
	int option;
	ea_t ea = BADADDR;
	size_t i;

	const char format[] =
			"STARTITEM 0\n"

			"Set Match\n"
			"<Match address:$:32:32::>\n\n"

			"Options :\n" 
			"<Propagate :C>>\n\n"
			;

	option = 1;
	if (AskUsingForm_c(format, &ea, &option))
	{
		s1 = eng->ulist->sigs[n-1];

		for (i=0; i<eng->ulist->num; i++)
		{
			s2 = eng->ulist->sigs[i];

			if (s2->startEA != ea || (s2->nfile == s1->nfile))
				continue;

			sig_set_matched_sig(s1, s2, DIFF_MANUAL);
			propagate_match(eng, s1, s2, option);

			refresh_chooser(title_match);
			refresh_chooser(title_identical);

			return 1;
		}

		warning("Address '%a' is not valid.", ea);
		return 0;
	}

	return 1;
}


/*------------------------------------------------*/
/* function : res_mtoi                            */
/* description: Switches element n from matched   */
/*              to identical list                 */
/*------------------------------------------------*/

static uint32 idaapi res_mtoi(void *obj,uint32 n)
{
	deng_t * d = (deng_t *)obj;

	d->mlist->sigs[n-1]->mtype = d->mlist->sigs[n-1]->msig->mtype = DIFF_MANUAL;

	siglist_add(d->ilist, d->mlist->sigs[n-1]);
	siglist_remove(d->mlist, n-1);

	refresh_chooser(title_identical);

	return 1;
}


/*------------------------------------------------*/
/* function : res_itom                            */
/* description: Switches element n from identical */
/*              to matched list                   */
/*------------------------------------------------*/

static uint32 idaapi res_itom(void *obj,uint32 n)
{
	deng_t * d = (deng_t *)obj;

	d->ilist->sigs[n-1]->mtype = d->ilist->sigs[n-1]->msig->mtype = DIFF_MANUAL;

	siglist_add(d->mlist, d->ilist->sigs[n-1]);
	siglist_remove(d->ilist, n-1);

	refresh_chooser(title_match);

	return 1;
}


/*------------------------------------------------*/
/* function : res_flagged                         */
/* description: Sets element as flagged/unflagged */
/*------------------------------------------------*/

static uint32 idaapi res_flagged(void *obj,uint32 n)
{
	deng_t * d = (deng_t *)obj;
	d->mlist->sigs[n-1]->flag = !d->mlist->sigs[n-1]->flag;

	refresh_chooser(title_match);

	return 1;
}


/*------------------------------------------------*/
/* function : display_matched                     */
/* description: Displays matched list             */
/*------------------------------------------------*/

static void display_matched(deng_t * eng)
{
	choose2(false,			  // non-modal window
		-1, -1, -1, -1,       // position is determined by Windows
		eng,                  // pass the created function list to the window
		qnumber(header_match),// number of columns
		widths_match,		  // widths of columns
		sizer_match,          // function that returns number of lines
		desc_match,           // function that generates a line
		title_match,	      // window title
		-1,                   // use the default icon for the window
		0,                    // position the cursor on the first line
		NULL,                 // "kill" callback
		NULL,                 // "new" callback
		NULL,                 // "update" callback
		graph_match,          // "edit" callback
		enter_match,          // function to call when the user pressed Enter
		close,                // function to call when the window is closed
		popup_match,          // use default popup menu items
		NULL);  

	eng->wnum++;

	add_chooser_command(title_match, "Unmatch", res_munmatch, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
	add_chooser_command(title_match, "Set as identical", res_mtoi, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
	add_chooser_command(title_match, "Flag/unflag", res_flagged, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);

	enable_chooser_item_attrs(title_match, 1);
}


/*------------------------------------------------*/
/* function : display_identical                   */
/* description: Displays identical list           */
/*------------------------------------------------*/

static void display_identical(deng_t * eng)
{
	choose2(false,			  // non-modal window
		-1, -1, -1, -1,       // position is determined by Windows
		eng,                  // pass the created function list to the window
		qnumber(header_match),// number of columns
		widths_match,		  // widths of columns
		sizer_identical,      // function that returns number of lines
		desc_identical,       // function that generates a line
		title_identical,	  // window title
		-1,                   // use the default icon for the window
		0,                    // position the cursor on the first line
		NULL,                 // "kill" callback
		NULL,                 // "new" callback
		NULL,                 // "update" callback
		graph_identical,      // "edit" callback
		enter_identical,      // function to call when the user pressed Enter
		close,                // function to call when the window is closed
		popup_match,          // use default popup menu items
		NULL);  

	eng->wnum++;

	add_chooser_command(title_identical, "Unmatch", res_iunmatch, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
	add_chooser_command(title_identical, "Set as matched", res_itom, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
}


/*------------------------------------------------*/
/* function : display_unmatched                   */
/* description: Displays unmatched list           */
/*------------------------------------------------*/

static void display_unmatched(deng_t * eng)
{
	choose2(false,			  // non-modal window
		-1, -1, -1, -1,       // position is determined by Windows
		eng,                  // pass the created function list to the window
		qnumber(header_unmatch),// number of columns
		widths_unmatch,		  // widths of columns
		sizer_unmatch,        // function that returns number of lines
		desc_unmatch,         // function that generates a line
		title_unmatch,	      // window title
		-1,                   // use the default icon for the window
		0,                    // position the cursor on the first line
		NULL,                 // "kill" callback
		NULL,                 // "new" callback
		NULL,                 // "update" callback
		graph_unmatch,        // "edit" callback
		enter_unmatch,        // function to call when the user pressed Enter
		close,                // function to call when the window is closed
		popup_unmatch,        // use default popup menu items
		NULL);                // use the same icon for all lines

	eng->wnum++;

	add_chooser_command(title_unmatch, "Set match", res_match, 0, -1, CHOOSER_POPUP_MENU | CHOOSER_MENU_EDIT);
}


/*------------------------------------------------*/
/* function : ui_callback                         */
/* description: Catchs lists to change bg color   */
/*------------------------------------------------*/

int idaapi ui_callback(void * data, int event_id, va_list va)
{
  if ( event_id == ui_get_chooser_item_attrs )  
  {
	  void * co = va_arg(va, void *);
	  uint32 n = va_arg(va, uint32);
	  chooser_item_attrs_t *attrs = va_arg(va, chooser_item_attrs_t *);
	  if (attrs != NULL)
	  {
		deng_t * d = (deng_t *)co;
		if (d && d->magic == 0x0BADF00D)
			if (d->mlist->sigs[n-1]->flag == 1)
				attrs->color = 0x908070;
	  }
  }

  return 0;
}


/*------------------------------------------------*/
/* function : display_results                     */
/* description: Displays diff results             */
/*------------------------------------------------*/

void display_results(deng_t * eng)
{
	hook_to_notification_point(HT_UI, ui_callback, NULL);

	display_matched(eng);
	display_unmatched(eng);
	display_identical(eng);
}
