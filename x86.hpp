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

#ifndef __PX86_H__
#define __PX86_H__

#include <ida.hpp>

unsigned char x86_get_byte(ea_t);
bool x86_remove_instr(unsigned char, ea_t);
bool x86_is_end_block(ea_t);
bool x86_is_direct_jump(ea_t ea);
ea_t x86_get_fake_jump(ea_t);

#endif