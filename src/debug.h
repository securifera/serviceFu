#pragma once

#include <stdio.h>

//debug message functions
#define VERBOSITY 6
#ifdef _DEBUG
	#define DbgFprintf(f, lvl, format, ...) DebugFprintf(f, lvl, format, __VA_ARGS__)
	#define DbgFwprintf(f, lvl, format, ...) DebugFwprintf(f, lvl, format, __VA_ARGS__)
#else
	#define DbgFprintf(...)
	#define DbgFwprintf(...)
#endif
void DebugFprintf(FILE* f, unsigned int lvl, const char *format, ...);
void DebugFwprintf(FILE* f, unsigned int lvl, const wchar_t *format, ...);
std::string GetLastErrorAsString(DWORD err);

extern unsigned int verbosity;
extern FILE* outlogfile;

//debug verbosity levels
#define PRINT_ERROR	1
#define PRINT_WARN	2
#define PRINT_INFO1	3
#define PRINT_INFO2	4
#define PRINT_WARN2 5
#define PRINT_INFO3	6