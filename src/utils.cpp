/*	Author:  barbarisch, b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#include <Windows.h>

#include "utils.h"
#include "debug.h"

void addPrivilegeToCurrentProcess(char* privilegeName)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValueA(NULL, privilegeName, &luid)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Couldn't lookup the privilege value. Error: 0x%x\n", GetLastError());
		return;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// Enable the privilege or disable all privileges.
	HANDLE currProc = GetCurrentProcess();
	HANDLE procToken;
	if(!OpenProcessToken(currProc, TOKEN_ADJUST_PRIVILEGES, &procToken)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Couldn't open the process token. Error: 0x%x\n", GetLastError());
		return;
	}

	DbgFprintf(outlogfile, PRINT_INFO1, "[.] Attempting to add privilege to this process...\n");
	if (!AdjustTokenPrivileges(procToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL)) {
		DbgFprintf(outlogfile, PRINT_ERROR, "[-] Adding privilege to this process didn't work. Error: 0x%x\n", GetLastError());
		return;
	} else {
		DbgFprintf(outlogfile, PRINT_INFO1, "[+] Added privilege to this process.\n");
	}

	CloseHandle(procToken);
	CloseHandle(currProc);
}