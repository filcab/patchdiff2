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


#ifndef __PARSER_H__
#define __PARSER_H__


#include "sig.hpp"
#include "options.hpp"

slist_t * parse_idb();
slist_t * parse_second_idb(char **, options_t *);
slist_t * parse_fct(ea_t, char);
slist_t * parse_second_fct(ea_t, char *, options_t *);

#endif