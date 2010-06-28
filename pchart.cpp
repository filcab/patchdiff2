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


#include <stack>

#include <pro.h>
#include <ida.hpp>
#include <funcs.hpp>
#include <gdl.hpp>
#include <xref.hpp>

#include "pchart.hpp"
#include "patchdiff.hpp"
#include "x86.hpp"

using namespace std;

extern cpu_t patchdiff_cpu;


ea_t get_fake_jump(ea_t ea)
{
	switch(patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		return x86_get_fake_jump(ea);
	default:
		return BADADDR;
	}
}


bool is_end_block(ea_t ea)
{
	switch(patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		return x86_is_end_block(ea);
	default:
		return false;
	}
}

ea_t get_direct_jump(ea_t ea)
{
	xrefblk_t xb;
	cref_t cr;
	flags_t f = getFlags(ea);
	bool b = xb.first_from(ea, XREF_FAR);
    if (!b) return BADADDR;

	cr = (cref_t)xb.type;
	if (!xb.iscode || !(cr == fl_JF || cr == fl_JN || cr == fl_F) || (f & FF_JUMP)) return BADADDR;

	switch(patchdiff_cpu)
	{
	case CPU_X8632:
	case CPU_X8664:
		if (x86_is_direct_jump(ea)) return xb.to;
	default:
		return BADADDR;
	}
}


bool pflow_chart_t::getJump(func_t * fct, qvector<ea_t> & list, pbasic_block_t & bl)
{
	xrefblk_t xb;
	cref_t cr;
	bool b, j, flow;
	qvector<pedge_t> tmp;
	qvector<pedge_t>::iterator pos;
	ea_t tea, ea = bl.endEA, end, jaddr;
	flags_t f;
	size_t k;
	int type;
	int cond;

	j = flow = false;

	end = get_item_end(ea);

	b = xb.first_from(ea, XREF_ALL);
	f = getFlags(ea);
	cond = x86_is_cond_jump_pos(ea);

	while (b)
	{
		cr = (cref_t)xb.type;
		if (xb.iscode && (cr == fl_JF || cr == fl_JN || cr == fl_F))
		{
			pedge_t ed;

			if (cr == fl_JF || cr == fl_JN)
			{
				j = true;
				type = 1;
			}
			else if (! (f & FF_JUMP))
			{
				flow = true;
				type = 2;
			}

			if (patchdiff_cpu == CPU_X8632 || patchdiff_cpu == CPU_X8664 || get_func_chunknum(fct, xb.to) >= 0)
			{
				jaddr = get_direct_jump(xb.to);
				if (jaddr == BADADDR)
					ed.ea = xb.to;
				else
					ed.ea = jaddr;

				ed.type = type;

				pos = tmp.end();

				if (patchdiff_cpu == CPU_X8632 || patchdiff_cpu == CPU_X8664)
				{
					if ( (cond == 1 && cr == fl_F) || (cond == 2 && cr != fl_F) )
						pos = tmp.begin();
				}
				else if (ed.ea == end)
					pos = tmp.begin();

				tmp.insert(pos, ed);
			}
		}

		b = xb.next_from();
	}

	tea = get_fake_jump(ea);
	if (tea != BADADDR)
	{
		pedge_t ed;

		j = true;
		ed.ea = tea;
		ed.type = 1;
	}

	if (j)
	{
		for (k=0; k<tmp.size(); k++)
		{
			pedge_t ed;

			ed.ea = tmp[k].ea;
			if (flow)
				ed.type = tmp[k].type;
			else
				ed.type = 3;

			if (xb.to != bl.startEA)
				list.push_back(tmp[k].ea);

			bl.succ.push_back(ed);
		}

		return true;
	}

	return false;
}


bool pflow_chart_t::check_address(ea_t ea)
{
	qvector<pbasic_block_t>::iterator it;

	for (it=blocks.begin(); it<blocks.end(); it++)
	{
		if (it->startEA == ea)
			return true;

		if (ea > it->startEA && ea < it->endEA)
		{
			pbasic_block_t bl;
			pedge_t ed;

			bl.startEA = ea;
			bl.endEA = it->endEA;
			bl.succ = it->succ;

			it->endEA = ea;
			it->succ.clear();

			ed.ea = ea;
			ed.type = 3;
			it->succ.push_back(ed);

			blocks.push_back(bl);

			return true;
		}
	}


	return false;
}


pflow_chart_t::pflow_chart_t(func_t * fct)
{
	ea_t ea;
	qvector<ea_t> to_trace;
	bool cont;
	flags_t f;

	to_trace.push_back(fct->startEA);

	while (!to_trace.empty())
	{
		ea = to_trace.front();
		to_trace.erase(to_trace.begin());

		if (check_address(ea))
			continue;

		pbasic_block_t bl;

		bl.startEA = ea;
		bl.endEA = ea;
		cont = true;

		while(cont)
		{
			ea = bl.endEA;
			f = getFlags(ea);

			if ( (!isFlow(f) && (ea != bl.startEA)) || !isCode(f) )
				break;

			if ( check_address(ea) )
			{
				pedge_t ed;

				ed.ea = ea;
				ed.type = 3;

				bl.succ.push_back(ed);
				break;
			}

			if ( getJump(fct, to_trace, bl) )
				cont = false;

			if ( is_end_block(ea) )
				break;

			bl.endEA = get_item_end(ea);
		}

		blocks.push_back(bl);
	}

	nproper = blocks.size();
}
