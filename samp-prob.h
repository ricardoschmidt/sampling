#ifndef SAMP_PROB_H
#define SAMP_PROB_H

#include <stdio.h>
#include <stdlib.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <pcap.h>
#include <string.h>
#include <algorithm>

#include <dirent.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <unistd.h>

#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)
#define ETHER_TYPE_ARP (0x0806)
#define ETHER_TYPE_IPV6 (0x86dd)

struct pcap_controls_t {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
} pcap_controls;

struct read_controls_t {
  char timescale_type;
  time_t timescale;
  char input_type;
  char *pcap_file;
  int fnum;
  char *files[MAXPATHLEN];
  char *dir;

	// variables for sampling
	char *infile;
	char *outfile;
	int p;
} read_controls;

struct print_vars_t {
  unsigned long int count;
} print_vars;

char* getSec(long int);
char* getMin(long int);
char* getHour(long int);
char* getDay(long int);
int tsMSec();
int tsSec();

int procFiles();
int procDir();

#endif
