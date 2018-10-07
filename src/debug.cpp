/*	Author:  barbarisch, b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#include <stdio.h>
#include <stdarg.h>
#include <Windows.h>
#include <string>

#include "debug.h"

FILE* outlogfile = stdout;
unsigned int verbosity = VERBOSITY;

//wrapper around printf to handles levels of verbosity
void DebugFprintf(FILE* f, unsigned int lvl, const char *format, ...)
{
#ifdef _DEBUG
	if(lvl <= verbosity) {
		if(f) {
			va_list args;
			va_start(args, format);

			vfprintf(f, format, args);

			va_end(args);
		}
	}
#endif
}

void DebugFwprintf(FILE* f, unsigned int lvl, const wchar_t *format, ...)
{
#ifdef _DEBUG
	if(lvl <= verbosity) {
		if(f) {
			va_list args;
			va_start(args, format);

			vfwprintf(f, format, args);

			va_end(args);
		}
	}
#endif
}

std::string GetLastErrorAsString(DWORD err)
{
    if(err == 0)
        return std::string(); //No error message has been recorded

    LPSTR messageBuffer = nullptr;
	DWORD dwFlags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    size_t size = FormatMessageA(dwFlags, NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

    std::string message(messageBuffer, size);

    //Free the buffer.
    LocalFree(messageBuffer);

    return message;
}