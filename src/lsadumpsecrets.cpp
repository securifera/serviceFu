#include <stdio.h>
#include <string>

#include "mimikatz\kuhl_m_lsadump.h"

#ifdef MIMIKATZLIB
	#include "lsadumpsecrets.h"
#endif

#pragma comment(lib, "ntdll.min.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "cryptdll.lib")
#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "shlwapi.lib")

#ifdef MIMIKATZLIB
int testmain(int argc, char** argv)
#else
int main(int argc, char** argv)
#endif
{
	kuhl_m_lsadump_secrets("sys.hiv", "sec.hiv");

	return 0;
}

void testlibfunc(std::string sysHive, std::string securityHive)
{
	kuhl_m_lsadump_secrets(sysHive.c_str(), securityHive.c_str());
}