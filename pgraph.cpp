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

#include "pgraph.hpp"
#include "sig.hpp"
#include "diff.hpp"


static int find_node(slist_t * sl, ea_t ea)
{
	size_t i;

	for(i=0; i<sl->num; i++)
		if (sl->sigs[i]->startEA == ea)
			return i;

	return -1;
}


/*------------------------------------------------*/
/* function : menu_callback                       */
/* description: Menu callback                     */
/*------------------------------------------------*/

static bool idaapi menu_callback(void *ud)
{
	int node;
	slist_t * sl = (slist_t *)ud;

	if (sl && sl->sigs && sl->sigs[0]->nfile == 1)
	{
		node = viewer_get_curnode(sl->gv);
		if (node >= 0)
			jumpto(sl->sigs[node]->startEA);
	}

	return true;
}


/*------------------------------------------------*/
/* function : graph_callback                      */
/* description: Graph callback                    */
/*------------------------------------------------*/

static int idaapi graph_callback(void * ud, int code, va_list va)
{
	int result = 0;

	switch ( code )
	{
	case grcode_layout_calculated:
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			slist_t * sl = (slist_t *)ud;

			if (sl->num != g->size())
			{
				warning("Graph layout is too complex to be displayed.\n");
				g->reset();
			}
		}
		break;

	case grcode_changed_current:
		{
			graph_viewer_t *v	= va_arg (va, graph_viewer_t *);
			int node			= va_argi(va, int);

			if (node != -1)
			{
				slist_t * sl = (slist_t *)ud;
				sl->dclk = true;
			}
		}
		break;

	case grcode_clicked:
		{
			slist_t * sl = (slist_t *)ud;
			sl->dclk = false;
		}
		break;

	case grcode_dblclicked:
		{
			graph_viewer_t *v   = va_arg(va, graph_viewer_t *);
			selection_item_t *s = va_arg(va, selection_item_t *);
			slist_t * sl = (slist_t *)ud;

			if ( s && s->is_node)
			{
				viewer_center_on(v, s->node);

				if (sl->sigs[s->node]->msig != NULL && sl->msl->gv != NULL)
					viewer_center_on(sl->msl->gv, find_node(sl->msl, sl->sigs[s->node]->matchedEA));

				sl->dclk = false;
			}
			else if ( sl->dclk || s )
			{
				int node;

				node = viewer_get_curnode(v);

				if (sl->sigs[node]->msig != NULL && sl->msl->gv != NULL)
					viewer_center_on(sl->msl->gv, find_node(sl->msl, sl->sigs[node]->matchedEA));

				sl->dclk = false;
			}
		}
		break;

	case grcode_user_refresh:
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			slist_t * sl = (slist_t *)ud;

			if ( g->empty() )
				g->resize(sl->num);

			for(size_t i = 0; i< sl->num; i++)
			{
				fref_t * fref;

				if (sl->sigs[i]->srefs)
				{
					fref = sl->sigs[i]->srefs->list;
					while(fref)
					{
						int pos = find_node(sl, fref->ea);
						
						if (pos != -1)
						{					
							edge_info_t ed;
							if (fref->type == 3)
								ed.color = 0xff0000;
							else if (fref->type == 2)
								ed.color = 0x0000ff;
							else
								ed.color = 0x006400;

							g->add_edge(i, pos, &ed);
						}

						fref = fref->next;
					}
				}
			}

			result = 1;
		}
		break;

	case grcode_user_text:
		{
			mutable_graph_t *g = va_arg(va, mutable_graph_t *);
			int node           = va_arg(va, int);
			const char **text  = va_arg(va, const char **);
			bgcolor_t *bgcolor = va_arg(va, bgcolor_t *);

			slist_t * sl = (slist_t *)ud;

			*text = sl->sigs[node]->dl.lines;

			if ( bgcolor != NULL )
			{
				*bgcolor = 0xFFFFFFFF;

				if (!sl->unique)
				{
					if (sl->sigs[node]->mtype == DIFF_UNMATCHED)
						*bgcolor = 0xcccccc;
					else if (sl->sigs[node]->sig != sl->sigs[node]->msig->sig)
						*bgcolor = 0x33cc;
					else if (sl->sigs[node]->id_crc)
						*bgcolor = 0x8cb4d2;
				}
			}
			result = 1;
			qnotused(g);
		}
		break;

	case grcode_destroyed:
		{
			slist_t * sl = (slist_t *)ud;

			sl->gv = NULL;
		}
		break;
	}

	return result;
}


template<size_t len>
void create_form_name(char (&dst)[len], slist_t *sl, int num)
{
	qsnprintf(dst, len, "IDB%d: %s", num, sl->sigs[0]->name);
}


/*------------------------------------------------*/
/* function : pgraph_create                       */
/* description: Creates s function graph          */
/* returns: true if the form was newly created    */
/*------------------------------------------------*/

static bool pgraph_create(slist_t *sl, int num)
{
	HWND hwnd = NULL;
	char form_name[512];
	char node_name[512];
	TForm *form;
	bool form_is_new = true;

	create_form_name(form_name, sl, num);
	qsnprintf(node_name, sizeof(node_name), "$ %s", form_name);
	
	form = find_tform(form_name);

	netnode id;
	bool already_existed = !id.create(node_name);
	if (form && already_existed)
	{
		form_is_new = false;
		switchto_tform(form, true);
		sl->gv = get_graph_viewer(form);
	}
	else
	{
		form = create_tform(form_name, &hwnd);
		if (hwnd)
		{
			sl->gv = create_graph_viewer(form, id, graph_callback, sl, 0);
			open_tform(form, FORM_TAB|FORM_MENU|FORM_QWIDGET);
			if (sl->gv)
			{
				viewer_fit_window(sl->gv);
				viewer_add_menu_item(sl->gv, "Jump to code", menu_callback, sl, NULL, 0);			
			}
		}
	}

	return form_is_new;
}


/*------------------------------------------------*/
/* function : pgraph_display                      */
/* description: Displays function graph           */
/*------------------------------------------------*/

void pgraph_display(slist_t * sl1, slist_t * sl2)
{
	graph_viewer_t *gv = NULL;

	sl1->msl = sl2;
	sl2->msl = sl1;

	sl1->unique = sl2->unique = false;

	bool sl1_new_form = pgraph_create(sl1, 1);
	bool sl2_new_form = pgraph_create(sl2, 2);
	if ((sl1_new_form || sl2_new_form) &&
		sl1->gv && sl2->gv)
	{
		// Only perform the docking for forms that were just created
		char buf[512], buf2[512];
		create_form_name(buf, sl1, 1);
		create_form_name(buf2, sl2, 2);
		set_dock_pos(buf2, buf, DP_RIGHT);
	}
}


void pgraph_display_one(slist_t * sl)
{
	sl->msl = NULL;
	sl->unique = true;

	pgraph_create(sl, sl->sigs[0]->nfile);
}
