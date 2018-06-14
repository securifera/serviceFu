#pragma once

#include <vector>

//various utilities functions
std::vector<std::string> splitStr(const std::string& s, const std::string& d);
void addPrivilegeToCurrentProcess(char* privilegeName);