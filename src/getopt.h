/*	Author:  barbarisch, b0yd
    Website: https://www.securifera.com
	License: https://creativecommons.org/licenses/by/4.0/
*/

#pragma once

extern int optind, opterr;
extern char *optarg;

int getopt(int argc, char *argv[], char *optstring);
