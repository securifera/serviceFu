/*	Benjamin DELPY `gentilkiwi`
	http://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/

	Modified: b0yd@securifera.com
	          Removed unnecessary code and added parameters to return lsadump data structures
*/
#include "kull_m_output.h"

FILE * logfile = NULL;
#ifndef MIMIKATZ_W2000_SUPPORT
wchar_t * outputBuffer = NULL;
size_t outputBufferElements = 0, outputBufferElementsPosition = 0;
#endif

void kprintf(PCWCHAR format, ...)
{

#ifdef _DEBUG // DEBUG preprocessor

#ifndef MIMIKATZ_W2000_SUPPORT
	int varBuf;
	size_t tempSize;
	wchar_t * tmpBuffer;
#endif
	va_list args;
	va_start(args, format);
#ifndef MIMIKATZ_W2000_SUPPORT
	if(outputBuffer)
	{
		varBuf = _vscwprintf(format, args);
		if(varBuf > 0)
		{
			if((size_t) varBuf > (outputBufferElements - outputBufferElementsPosition - 1)) // NULL character
			{
				tempSize = (outputBufferElements + varBuf + 1) * 2; // * 2, just to be cool
				if(tmpBuffer = (wchar_t *) LocalAlloc(LPTR, tempSize * sizeof(wchar_t)))
				{
					RtlCopyMemory(tmpBuffer, outputBuffer, outputBufferElementsPosition * sizeof(wchar_t));
					LocalFree(outputBuffer);
					outputBuffer = tmpBuffer;
					outputBufferElements = tempSize;
				}
				else wprintf(L"Erreur LocalAlloc: %u\n", GetLastError());
				//if(outputBuffer = (wchar_t *) LocalReAlloc(outputBuffer, tempSize * sizeof(wchar_t), LPTR))
				//	outputBufferElements = tempSize;
				//else wprintf(L"Erreur ReAlloc: %u\n", GetLastError());
			}
			varBuf = vswprintf_s(outputBuffer + outputBufferElementsPosition, outputBufferElements - outputBufferElementsPosition, format, args);
			if(varBuf > 0)
				outputBufferElementsPosition += varBuf;
		}
	}
#endif
#ifndef _POWERKATZ
#ifndef MIMIKATZ_W2000_SUPPORT
	else
#endif
	{
		vwprintf(format, args);
		fflush(stdout);
	}
#endif
	if(logfile)
	{
		vfwprintf(logfile, format, args);
		fflush(logfile);
	}
	va_end(args);

#endif // DEBUG preprocessor
}
