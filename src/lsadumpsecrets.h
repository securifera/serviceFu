#pragma once

#include <string>
#include "main.h"

extern void dump_svc_secrets(PSVC_STRUCT *svc_arr, size_t svc_arr_size, std::string sysHive, std::string securityHive);