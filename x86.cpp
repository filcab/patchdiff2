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


#include <ida.hpp>
#include <bytes.hpp>

#include "x86.hpp"
#include "patchdiff.hpp"

extern cpu_t patchdiff_cpu;


/*------------------------------------------------*/
/* function : x86_is_rex_prefix                   */
/* arguments: unsigned char val                   */
/* description: detects if instruction is a Rex   */
/*              prefix                            */
/*------------------------------------------------*/

bool x86_is_rex_prefix(unsigned char val)
{
	if (val >= 0x40 && val <= 0x4F)
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : x86_is_push_register                */
/* arguments: unsigned char val                   */
/* description: detects if instruction is push reg*/
/*------------------------------------------------*/

bool x86_is_push_register (unsigned char val)
{
	switch (val)
	{
	case 0x50:	// push eax
	case 0x51:	// push ecx
	case 0x52:	// push edx
	case 0x53:	// push ebx
	case 0x54:	// push esp
	case 0x55:	// push ebp
	case 0x56:	// push esi
	case 0x57:	// push edi
		return 1;

	default:
		return 0;
	}
}

/*------------------------------------------------*/
/* function : x86_is_pop_register                 */
/* arguments: unsigned char val                   */
/* description: detects if instruction is pop reg */
/*------------------------------------------------*/

bool x86_is_pop_register (unsigned char val)
{
	switch (val)
	{
	case 0x58:	// pop eax
	case 0x59:	// pop ecx
	case 0x5A:	// pop edx
	case 0x5B:	// pop ebx
	case 0x5C:	// pop esp
	case 0x5D:	// pop ebp
	case 0x5E:	// pop esi
	case 0x5F:	// pop edi
		return 1;

	default:
		return 0;
	}
}


/*------------------------------------------------*/
/* function : x86_is_inc_register                 */
/* arguments: unsigned char val                   */
/* description: detects if instruction is inc reg */
/*------------------------------------------------*/

bool x86_is_inc_register (unsigned char val)
{
	switch (val)
	{
	case 0x40:	// inc eax
	case 0x41:	// inc ecx
	case 0x42:	// inc edx
	case 0x43:	// inc ebx
	case 0x44:	// inc esp
	case 0x45:	// inc ebp
	case 0x46:	// inc esi
	case 0x47:	// inc edi
		return 1;

	default:
		return 0;
	}
}

/*------------------------------------------------*/
/* function : x86_is_dec_register                 */
/* arguments: unsigned char val                   */
/* description: detects if instruction is dec reg */
/*------------------------------------------------*/

bool x86_is_dec_register (unsigned char val)
{
	switch (val)
	{
	case 0x48:	// dec eax
	case 0x49:	// dec ecx
	case 0x4A:	// dec edx
	case 0x4B:	// dec ebx
	case 0x4C:	// dec esp
	case 0x4D:	// dec ebp
	case 0x4E:	// dec esi
	case 0x4F:	// dec edi
		return 1;

	default:
		return 0;
	}
}




/*------------------------------------------------*/
/* function : is_nop                              */
/* arguments: unsigned char _byte                 */
/* description: detect if instruction is nop      */
/*              (nop, mov reg, reg, ...)          */
/*------------------------------------------------*/

bool x86_is_nop (unsigned char _byte, ea_t ea)
{
	unsigned char val;
	unsigned short val2;
	unsigned long val3;

	if (patchdiff_cpu == CPU_X8664 && x86_is_rex_prefix(_byte))
	{
		ea++;
		_byte = get_byte(ea+1);
	}

	// mov reg, reg - xchg reg, reg
	if (_byte == 0x8A || _byte == 0x8B || _byte == 0x87 || _byte == 0x86)
	{
		val = get_byte(ea+1);
		if ( (val == 0xC0) || // mov eax, eax (al, al)
			 (val == 0xC9) || // mov ecx, ecx
			 (val == 0xDB) || // mov ebx, ebx
			 (val == 0xD2) || // mov edx, edx
			 (val == 0xF6) || // mov esi, esi
			 (val == 0xFF) || // mov edi, edi
			 (val == 0xE4) || // mov esp, esp
			 (val == 0xED) )  // mov ebp, ebp
			return true;
	}
	if (_byte == 0x8D)
	{
		val = get_byte(ea+1);
		if ( (val == 0x00) || // lea eax, [eax]
			 (val == 0x09) || // lea ecx, [ecx]
			 (val == 0x42) || // lea edx, [edx]
			 (val == 0x4b) || // lea ebx, [ebx]
			 (val == 0x36) || // lea esi, [esi]
			 (val == 0x3f) )  // lea edi, [edi]
		{
			 return true;
		}
		else if ( (val == 0x40) || // lea eax, [eax+0]
				  (val == 0x49) || // lea ecx, [ecx+0]
				  (val == 0x52) || // lea edx, [edx+0]
				  (val == 0x5b) || // lea ebx, [ebx+0]
				  (val == 0x6d) || // lea ebp, [ebp+0]
				  (val == 0x76) || // lea esi, [esi+0]
				  (val == 0x7f) )  // lea edi, [edi+0]
		{
			val = get_byte(ea+2);
			if (val == 0x00)
			  return true;
		}
		else if ( (val == 0x80) || // lea eax, [eax+0x00000000]
				  (val == 0x89) || // lea ecx, [ecx+0x00000000]
				  (val == 0x92) || // lea edx, [edx+0x00000000]
				  (val == 0x9b) || // lea ebx, [ebx+0x00000000]
				  (val == 0xad) || // lea ebp, [ebp+0x00000000]
				  (val == 0xB6) || // lea esi, [esi+0x00000000]
				  (val == 0xBf) )  // lea edi, [edi+0x00000000]
		{
			val3 = get_long(ea+2);
			if (val3 == 0x00)
			  return true;
		}
		else if (val == 0xb4)
		{
			val = get_byte(ea+2);
			if (val == 0x26)
			{
				val3 = get_long(ea+3);
				if (val3 == 0x00)	// lea esi, [esi+0x00000000]
					return true;
			}
		}
		else if (val == 0x24)
		{
			val = get_byte(ea+2);
			if (val == 0x24)   // lea esp, [esp]
			  return true;
		}
		else if (val == 0x64)
		{
			val2 = get_word(ea+2);
			if (val2 == 0x24)   // lea esp, [esp+0]
			  return true;
		}
		else if (val == 0xa4)
		{
			val = get_byte(ea+2);
			if (val == 0x24)
			{
				val3 = get_long(ea+3);
				if (val3 == 0x00)	// lea esp, [esp+0x00000000]
					return true;
			}
		}
	}

	// nop
	if (_byte == 0x90)
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : x86_remove_instr                    */
/* arguments: unsigned char byte, ea_t ea         */
/* description: Returns true is the instruction   */
/*              must be ignored                   */
/*------------------------------------------------*/

bool x86_remove_instr(unsigned char byte, ea_t ea)
{
	// removes nop
	if (x86_is_nop(byte, ea))
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : x86_convert_16bit_rep               */
/* arguments: unsigned char val, instr address    */
/* description: converts byte if instruction is a */
/*              16 bit rep/repe/repz/repne/repnz  */
/* notes: detects changes like 66 F3 -> F3 66     */
/*------------------------------------------------*/

bool x86_convert_16bit_rep(unsigned char * byte, ea_t ea)
{
	unsigned char byte2;

	if (*byte == 0x66)
	{
		byte2 = get_byte(ea+1);
		if (byte2 == 0xF3 || byte2 == 0xF2)
		{
			*byte = byte2;
			return true;
		}
	}

	return false;
}


/*------------------------------------------------*/
/* function : x86_convert_cond_jump               */
/* arguments: unsigned char val, instr address    */
/* description: converts byte if instruction is a */
/*              conditionnal jump. If jnz returns */
/*              jz, if jne return je, ...         */
/*------------------------------------------------*/

bool x86_convert_cond_jump(unsigned char * byte, ea_t ea)
{
	unsigned char byte2 = *byte;

	if (byte2 == 0x0F)
	{
		byte2 = get_byte(ea+1) - 0x10;
	}

	if (byte2 >= 0x70 && byte2 <= 0x7F)
	{
		switch (byte2)
		{
		case 0x77:  // ja -> jb
			*byte = 0x72;
			break;
		case 0x73:  // jae -> jbe
			*byte = 0x76;
			break;
		case 0x75:  // jnz -> jz
			*byte = 0x74;
			break;
		case 0x7F:  // jg -> jl
			*byte = 0x7C;
			break;
		case 0x7D:  // jge -> jle
			*byte = 0x7E;
			break;
		case 0x71:  // jno -> jo
			*byte = 0x70;
			break;
		case 0x7B:  // jnp -> jp
			*byte = 0x7A;
			break;
		case 0x79:  // jns -> js
			*byte = 0x78;
			break;
		default:
			*byte = byte2;
		}

		return true;
	}

	return false;
}


/*------------------------------------------------*/
/* function : x86_convert_cond_jump               */
/* arguments: unsigned char val, instr address    */
/* description: converts byte if instruction is a */
/*              conditionnal jump. If jnz returns */
/*              jz, if jne return je, ...         */
/*------------------------------------------------*/

int x86_is_cond_jump_pos(ea_t ea)
{
	unsigned char byte2 = get_byte(ea);

	if (byte2 == 0x0F)
	{
		byte2 = get_byte(ea+1) - 0x10;
	}

	if (byte2 >= 0x70 && byte2 <= 0x7F)
	{
		switch (byte2)
		{
		case 0x77: //ja
		case 0x72: //jb
		case 0x74: //jz
		case 0x7F: //jg
		case 0x7C: //jl
		case 0x70: //jo
		case 0x7A: //jp
		case 0x78: //js
			return 1;
		default:
			return 2;
		}
	}

	return 0;
}


/*------------------------------------------------*/
/* function : x86_get_fake_jump                   */
/* arguments: ea_t ea                             */
/* description: Returns jump for jump $5/$2       */
/*------------------------------------------------*/

ea_t x86_get_fake_jump(ea_t ea)
{
	unsigned char byte;
	unsigned long l;

	byte = get_byte(ea);
	if (byte == 0xE9)
	{
		l = get_long(ea+1);
		if (l == 0)
			return get_item_end(ea);
	}
	else if (byte == 0xeb)
	{
		byte = get_byte(ea+1);
		if (byte == 0)
			return get_item_end(ea);
	}

	return BADADDR;
}

/*------------------------------------------------*/
/* function : x86_is_direct_jump                  */
/* arguments: ea_t ea                             */
/* description: Returns TRUE if a direct jump     */
/*------------------------------------------------*/

bool x86_is_direct_jump(ea_t ea)
{
	unsigned char byte;

	byte = get_byte(ea);
	switch (byte)
	{
	case 0xE9:
	case 0xEA:
	case 0xEB:
	case 0xFF:
		return true;
	default:
		return false;
	}

	return false;
}


/*------------------------------------------------*/
/* function : x86_is_end_block                    */
/* arguments: ea_t ea                             */
/* description: Returns true on int 3             */
/*------------------------------------------------*/

bool x86_is_end_block(ea_t ea)
{
	if (get_byte(ea) == 0xCC)
		return true;

	return false;
}


/*------------------------------------------------*/
/* function : x86_get_byte                        */
/* arguments: unsigned char _byte                 */
/* description: Returns opcode                    */
/* note: convert push/pop registers and remove rex*/
/*       prefix                                   */
/*------------------------------------------------*/

unsigned char x86_get_byte(ea_t ea)
{
	unsigned char byte;

	byte = get_byte(ea);

	if (patchdiff_cpu == CPU_X8664 && x86_is_rex_prefix(byte))
	{
		ea++;
		byte = get_byte(ea);
	}

	if (x86_is_push_register (byte))
		byte = 0x50;  // push eax
	else if (x86_is_pop_register (byte))
		byte = 0x58;  // pop eax
	else if (x86_is_inc_register(byte))
		byte = 0x40;  // inc eax
	else if (x86_is_dec_register(byte))
		byte = 0x48;  // dec eax
	
	x86_convert_16bit_rep(&byte, ea);
	x86_convert_cond_jump(&byte, ea);

	return byte;
}