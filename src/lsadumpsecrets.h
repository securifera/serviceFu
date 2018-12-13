#pragma once

#include <string>
#include "main.h"

extern void dump_svc_secrets(HKEY passedKey, PSVC_STRUCT *svc_arr, size_t svc_arr_size);