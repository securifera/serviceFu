#include <Windows.h>

#include "utils.h"
#include "debug.h"

std::vector<std::string> splitStr(const std::string& s, const std::string& d)
{
	std::vector<std::string> output;
    std::string::size_type prev_pos = 0, pos = 0;

    while((pos = s.find(d[0], pos)) != std::string::npos) {
		if((pos+d.size() <= s.size()) && (d.compare(s.substr(pos, d.size())) == 0)) {
			std::string substring(s.substr(prev_pos, pos-prev_pos));
			output.push_back(substring);
			prev_pos = pos+d.size();
			pos += d.size();
		}
		else {
			prev_pos = ++pos;
		}
    }

	std::string last(s.substr(prev_pos, pos-prev_pos));
	if(last.size() > 0) {
		output.push_back(last); // Last word
	}

    return output;
}

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