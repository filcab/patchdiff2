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

#ifndef __DISPLAY_H__
#define __DISPLAY_H__

#include "diff.hpp"


// column widths
static const int widths_match[] = { 5, 32, 32, 16, 16, 4, 16, 16 };
static const int widths_unmatch[] = { 5, 32, 16, 8, 8, 8};

// column headers
static const char *header_match[] =
{
	"Engine",
	"Function 1",
	"Function 2",
	"Address 1",
	"Address 2",
	"CRC",
	"CRC1",
	"CRC2"
};

static const char *header_unmatch[] =
{
	"File",
	"Function name",
	"Function address",
	"Sig",
	"Hash",
	"CRC"
};

static const char * popup_null = "\0\0\0\0";

static const char * popup_match[] =
{
	popup_null,
	popup_null,
	"Display Graphs",
	NULL,
};

static const char * popup_unmatch[] =
{
	popup_null,
	popup_null,
	"Display Graph",
	NULL,
};


static const char* title_match = "Matched Functions";
static const char* title_unmatch = "Unmatched Functions";
static const char* title_identical = "Identical Functions";


void display_results(deng_t *);

int ui_callback(void * data, int event_id, va_list va);

#endif
