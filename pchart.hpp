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


#ifndef __PCHART_H__
#define __PCHART_H__

#include "precomp.hpp"

struct pedge_t
{
	ea_t ea;
	int type;
};

struct pbasic_block_t : public area_t
{
  qvector<pedge_t> succ; // list of node successors
  qvector<pedge_t> pred; // list of node predecessors
};

class pflow_chart_t
{
private:
	bool check_address(ea_t ea);
	bool getJump(func_t * fct, qvector<ea_t> & list, pbasic_block_t & bl);

public:
	typedef qvector<pbasic_block_t> blocks_t;
	blocks_t blocks;
	int nproper;

	idaapi pflow_chart_t(func_t *_pfn);

	int idaapi nsucc(int node) const { return int(blocks[node].succ.size()); }
	int idaapi succ(int node, int i) const 
	{ 
		int k;

		for (k=0; k<nproper; k++)
			if (blocks[k].startEA == blocks[node].succ[i].ea)
				return k;

		return -1;
	}
	//int idaapi npred(int node) const { return (int)blocks[node].pred.size(); }
	int idaapi npred(int) const { return 0; }
	int idaapi pred(int node, int i) const
	{ 
		return -1;

		int k;

		for (k=0; k<nproper; k++)
			if (blocks[k].startEA == blocks[node].pred[i].ea)
				return k;

		return -1;
	}
};

ea_t get_direct_jump(ea_t ea);

#endif
