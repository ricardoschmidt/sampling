/*
 * samp-nn-random.cc
 *
 * This program creates sampling N:N random from a given input pcap file.
 *
 * Ricardo de O. Schmidt
 * April 7, 2013
 *
 * Design and Analysis of Communication Systems (DACS)
 * University of Twente (UT)
 * The Netherlands
 *
 * USAGE
 *  ./samp-n-1 <n> <pcap file>
 *
 * ABOUT THE OUTPUT
 *  See printing functions.
 *
 * WARNING
 *  This software does not consider packets where the length of TCP/IP payload
 *  is equal to zero.
 *
 */

#include "samp-nn-random.h"

const char* dumpname;

typedef struct {
  u_int16_t val;
} __attribute__((packed)) unaligned_u_int16_t;

#define EXTRACT_16BITS(p) \
  ((u_int16_t)ntohs(((const unaligned_u_int16_t *)(p))->val))

#define PRINT_LIMIT " "

struct print_ts_t {
  long int ml, bytes;
  int line_id;
} print_ts;


int tsSec() {

  /* packet reading variables */
  int ether_type, ether_offset, defTime = -1, fragcount=0;
  struct pcap_pkthdr header;
  const u_char *packet;
  u_char *pkt_data;
  struct ip *ip_hdr;
	struct tcphdr *tcp_hdr;
	struct udphdr *udp_hdr;
	size_t caplen, iph_len, tcph_len;
	const size_t udph_len = 8;
	const size_t icmph_len = 8;
  u_int16_t off;

  /* control and informative variables */
  long int cur_ml, next_ml, pkt_ml, acc_bytes = 0;
  cur_ml = next_ml = pkt_ml = -1;
  int line_num = 0; // line ID for printing

	// dump file to write sampled packets
	pcap_dumper_t *dumpfile;
	const char* dumpname = read_controls.outfile;
	dumpfile = pcap_dump_open(pcap_controls.handle, dumpname);
	if (dumpfile == NULL) {
		printf("open dumpfile error\n");
		return 0;
	}

	// sampling controls
	unsigned int sampled = 0, totsampled = 0, pktcount = 0, rnum = 0, totpkt = 0, assigned = 0,
							 nogo = 0;
	int pick[read_controls.n1];

	// pick first random number(s)
	srand(time(NULL));
	for (int i=0; i<read_controls.n1; i++) {
		do {
			rnum = rand()%read_controls.n2+1;
			if (assigned > 0) {
				for (int j=0; j<assigned; j++) {
					if (pick[j] == rnum) {
						rnum = 0;
						break;
					}
				}
			}
		} while (rnum == 0);
		pick[i] = rnum;
		assigned++;
	}

	// sort pick array
	int cur=0,next=0,pos=0,moves=0;
	if (read_controls.n1 > 1) {
		while (1) {
			if (moves == read_controls.n1-1) {
				break;
			}
			pos=0;
			while (pos < read_controls.n1-1) {
				cur = pick[pos];
				next = pick[pos+1];
				if (cur > next) {
					pick[pos+1] = cur;
					pick[pos] = next;
				}
				pos++;
			}
			moves++;
		}
	}

  /* loop for packet-by-packet */
  while (packet = pcap_next(pcap_controls.handle, &header)) {
    /* packet header */
    pkt_data = (u_char*)packet;

		caplen = header.caplen;
		/* check if we have a full Ethernet header */
		if (caplen < 14) {
			continue;
		}
		caplen -= 14;

    /* parse Ethernet header */
    ether_type = ((int)(pkt_data[12]) << 8) | (int)pkt_data[13];
    if (ether_type == ETHER_TYPE_IP || ether_type == ETHER_TYPE_ARP) {
			ether_offset = 14;
		}
    else if (ether_type == ETHER_TYPE_8021Q) {
			/* test 802.1q header */
			if (caplen < 4) {
				continue;
			}
			ether_offset = 18;
			caplen -= 4;
		}
    else {
			/* FIXME - do not consider other ethernet types for now */
      continue;
    }

    /* get IP header */
    pkt_data += ether_offset; // skip Ethernet header
    ip_hdr = (struct ip*)pkt_data; // pointer to an IP header structure

		/* check IPv4 header minimum size */
		if (caplen < 1) {
			continue;
		}
		iph_len = ip_hdr->ip_hl * 4;
		/* check IPv4 header size */
		if (caplen < iph_len) {
			continue;
		}
		caplen -= iph_len;

		pkt_data += iph_len; // skip IP header
		if (ip_hdr->ip_p == 6) { // TCP
			tcp_hdr = (struct tcphdr*)pkt_data; // pointer to an TCP header structure
			tcph_len = tcp_hdr->doff * 4;
			/* check TCP header size */
			if (caplen < 13 || caplen < tcph_len) {
				continue;
			}
			caplen -= tcph_len;
		}
		else if (ip_hdr->ip_p == 17) { // UDP
			udp_hdr = (struct udphdr*)pkt_data; // pointer to an UDP header structure
			/* check UDP header size */
			if (caplen < udph_len) {
				continue;
			}
			caplen -= udph_len;
		}
		else if (ip_hdr->ip_p == 1) { // ICMP
			/* check ICMP header size */
			if (caplen < icmph_len) {
				continue;
			}
			caplen -= icmph_len;
		}
		else { // other protocols
			continue;
		}

/* SAMPLING N:N - BEGIN */

		pktcount++;
		totpkt++;
		//printf("pkt %d\n",pktcount);

		// is this the packet to pick?
		if (sampled < read_controls.n1) {
			if (pktcount == pick[sampled]) {
				//printf(" - sampled [%d]\n", pick[sampled]);
				pcap_dump((unsigned char *)dumpfile, &header, packet);
				sampled++;
				totsampled++;
			}
		}

		if (pktcount == read_controls.n2) {
			// reached the interval size
			pktcount = 0;
			sampled = 0;

			// pick next random number(s)
			assigned = 0;
			for (int i=0; i<read_controls.n1; i++) {
				do {
					rnum = rand()%read_controls.n2+1;
					if (assigned > 0) {
						for (int j=0; j<assigned; j++) {
							if (pick[j] == rnum) {
								rnum = 0;
								break;
							}
						}
					}
				} while (rnum == 0);
				pick[i] = rnum;
				assigned++;
			}
		}

/* SAMPLING N:N - END */

  }

	//fprintf(stdout, "%d out of %d packets sampled\n", totsampled, totpkt);
	fprintf(stdout, "%d %d\n", totsampled, totpkt);

  return 0;
}

int procFiles() {
	if ((pcap_controls.handle = pcap_open_offline(read_controls.infile, pcap_controls.errbuf)) == NULL) {
  	fprintf(stderr, "ERROR: procFiles()\n%s\nexiting...\n", pcap_controls.errbuf);
		return 0;
	}

	if (tsSec() != 0) {
		fprintf(stderr, "ERROR: tsSec()\nexiting...\n");
		return 0;
	}

	pcap_close(pcap_controls.handle);

  return 0;
}

int main(int argc, char **argv) {
  // check if all arguments were provided
  if (argc < 5) {
    fprintf(stderr, "Usage:\n# %s <N1> <N2> <pcap_file> <dump_file>\n", argv[0]);
    exit(1);
  }

	read_controls.n1 = atoi(argv[1]);
	read_controls.n2 = atoi(argv[2]);
	read_controls.infile = argv[3];
	read_controls.outfile = argv[4];

	if (read_controls.n1 >= read_controls.n2) {
		fprintf(stderr, "N1 must be less than N2\n");
		return 0;
	}

	procFiles();

  return 0;
}
