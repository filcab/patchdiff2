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

#include "ppc.hpp"
#include "patchdiff.hpp"

extern cpu_t patchdiff_cpu;


/*------------------------------------------------*/
/* function : ppc_is_nop                          */
/* arguments: unsigned char _byte                 */
/* description: detects if instruction is a nop   */
/*              (mr rA, rA)                       */
/*------------------------------------------------*/

bool ppc_is_nop (unsigned char _byte, ea_t ea)
{
	unsigned char s, a, b, rc;
	unsigned short v;
	unsigned long l;

	_byte = get_byte(ea) >> 2;

	// or rS, rA, rB
	if (_byte == 31)
	{
		v = get_word(ea);
		s = (v >> 5) & 0x1F;
		a = v & 0x1F;

		if (s == a)
		{
			v = get_word(ea+2);

			b = v >> 11;
			rc = v & 1;
			v = (v >> 1) & 0x3FF;

			if (b == s && v == 444 && !rc)
				return true;
		}
	}
	// nop: ori 0,0,0
	else if (_byte == 24)
	{
		l = get_long(ea);
		if (l == 0x60000000)
			return true;
	}

	return false;
}


/*------------------------------------------------*/
/* function : ppc_remove_instr                    */
/* arguments: unsigned char byte, ea_t ea         */
/* description: Returns true is the instruction   */
/*              must be ignored                   */
/*------------------------------------------------*/

bool ppc_remove_instr(unsigned char byte, ea_t ea)
{
	if (ppc_is_nop(byte, ea))
		return true;

	/*
	// if not addi (li)
	if (byte != 14)
		return false;

	// removes li, rD, 0  (addi rD, rA, 0 with rA == 0)
	b = get_byte(ea+1) & 0x1F;
	if (!b)
	{
		s = get_word(ea+2);
		if (s == 0)
			return true;
	}
	*/

	return false;
}

/*------------------------------------------------*/
/* function : ppc_get_byte                        */
/* arguments: unsigned char _byte                 */
/* description: Returns opcode                    */
/*------------------------------------------------*/

unsigned char ppc_get_byte(ea_t ea)
{
	unsigned char byte;
	unsigned short v;

	byte = get_byte(ea) >> 2;

	if (byte == 31)
	{
		v = get_word(ea+2);
		v = (v >> 1) & 0xFF;
		if (v < 65) v += 65;

		byte = (unsigned char)v;
	}
	

	return byte;
}
