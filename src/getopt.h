#pragma once

extern int optind, opterr;
extern char *optarg;

int getopt(int argc, char *argv[], char *optstring);
