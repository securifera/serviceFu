/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#pragma once
#include "globals.h"
#include <io.h>
#include <fcntl.h>

extern FILE * logfile;
#ifndef MIMIKATZ_W2000_SUPPORT
extern wchar_t * outputBuffer;
extern size_t outputBufferElements, outputBufferElementsPosition;
#endif

void kprintf(PCWCHAR format, ...);