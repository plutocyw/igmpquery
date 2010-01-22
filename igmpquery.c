/*
 * Copyright (c) 2010, Jim Hollinger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Jim Hollinger nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL JIM HOLLINGER BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This software is based on the WinPcap sendpack.c example program
 * and requires the WinPcap library: http://www.winpcap.org/.
 *
 */

/*
 * IGMPv2 query generator
 *
 * Transmits a Internet Group Management Protocol (IGMP) v2 general query
 * to all active IPv4 network interfaces. Queries are sent to the
 * all-hosts multicast group: 224.0.0.1.
 * All IGMP aware hosts that have joined a multicast group should respond.
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

#define VERSION_STR  "V1.0"

/* Convert a numeric IPv4 address to a string */
#define IPTOSBUFFERS    (12)
char *iptos(u_long in) {
	static char output[IPTOSBUFFERS][3*4+3+1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (((which + 1) == IPTOSBUFFERS) ? 0 : which + 1);
	_snprintf_s(output[which], sizeof (output[which]), sizeof (output[which]),
		"%d.%d.%d.%d", p[0], p[1], p[2], p[3]);

	return output[which];
}

/* Convert a numeric IPv6 address to a string */
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen) {
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof (struct sockaddr_in6);
#else
	sockaddrlen = sizeof (struct sockaddr_storage);
#endif

	if (getnameinfo(sockaddr, 
		sockaddrlen, 
		address, 
		addrlen, 
		NULL, 
		0, 
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

/* Print all the available information on the given interface */
void ifprint(pcap_if_t *d) {
	pcap_addr_t *a;
	char ip6str[128];

	/* Name */
	printf("%s\n", d->name);

	/* Description */
	if (d->description) {
		printf("\tDescription: %s\n", d->description);
	}

	/* Loopback Address*/
	if (d->flags) {
		printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
	}

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family) {

		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n",
					iptos(((struct sockaddr_in *) a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n",
					iptos(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n",
					iptos(((struct sockaddr_in *) a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n",
					iptos(((struct sockaddr_in *) a->dstaddr)->sin_addr.s_addr));
			break;

		case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof (ip6str)));
			break;

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}

/* Compute 16-bit one's complement of the one's complement sum */
void computeAndStoreIpChecksum(u_short *src, int short_len, u_short *dst) {
	u_int sum = 0;
	u_short checksum = 0;
	u_char  *dest = (u_char *) dst;
	int i;

	for (i = 0; i < short_len; i++) {
		sum += src[i];
	}
	checksum = (u_short) (sum & 0x0FFFF) + (u_short) (sum >> 16);
	checksum = ~checksum;
	dest[0] = (u_char) (checksum & 0x0FF);
	dest[1] = (u_char) (checksum >> 8);
}

/* Transmit an IGMPv2 general query */
int igmpQuery(const char *dev, u_long src_addr, u_long dst_addr, u_char ttl) {
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[128];
	int n;

	/* Open the adapter */
	if ((fp = pcap_open_live(dev,		// name of the device
		65536,			// portion of the packet to capture. It doesn't matter in this case 
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
		)) == NULL)
	{
		fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap\n\n", dev);
		return 2;
	}

	/* MAC header */
	{
		/* Destination MAC Address: IPv4mcast (01:00:5e:7f:ff:ff) */
		packet[0]  = 0x01;
		packet[1]  = 0x00;
		packet[2]  = 0x5E;
		packet[3]  = (u_char) ((dst_addr >>  8) & 0x07F);
		packet[4]  = (u_char) ((dst_addr >> 16) & 0x0FF);
		packet[5]  = (u_char) ((dst_addr >> 24) & 0x0FF);

		/* Source MAC Address: Cisco_1d:37:e8 (00:24:98:1d:37:e8) */
		packet[6]  = 0x00;
		packet[7]  = 0x24;
		packet[8]  = 0x98;
		packet[9]  = 0x1D;
		packet[10] = 0x37;
		packet[11] = 0xE8;

		/* Ether Type: IP (0x0800) */
		packet[12] = 0x08;
		packet[13] = 0x00;
	}

	/* IP header */
	{
		/* Version: 4 (IP); Header length: 20 bytes */
		packet[14] = (4 << 4) | (20 / 4);

		/* Differentiated Services: 0x00 */
		packet[15] = 0x00;

		/* Total Length: MAC header length + IP header length */
		packet[16] = 0;
		packet[17] = 20 + 8;

		/* Identification: 0x0095 (149) */
		packet[18] = 0x00;
		packet[19] = 0x95;

		/* Flags: 0x00 */
		packet[20] = 0x00;

		/* Fragment offset: 0 */
		packet[21] = 0x00;

		/* Time to live */
		packet[22] = ttl;

		/* Protocol: IGMP */
		packet[23] = 0x02;

		/* Header checksum: to be filled in */
		packet[24] = 0x00;
		packet[25] = 0x00;

		/* Source */
		packet[26] = (u_char) ((src_addr >>  0) & 0x0FF);
		packet[27] = (u_char) ((src_addr >>  8) & 0x0FF);
		packet[28] = (u_char) ((src_addr >> 16) & 0x0FF);
		packet[29] = (u_char) ((src_addr >> 24) & 0x0FF);

		/* Destination */
		packet[30] = (u_char) ((dst_addr >>  0) & 0x0FF);
		packet[31] = (u_char) ((dst_addr >>  8) & 0x0FF);
		packet[32] = (u_char) ((dst_addr >> 16) & 0x0FF);
		packet[33] = (u_char) ((dst_addr >> 24) & 0x0FF);

		computeAndStoreIpChecksum((u_short *) &packet[14], 20 / 2, (u_short *) &packet[24]);
	}

	/* IGMPv2 packet */
	{
		/* Type: Membership Query */
		packet[34] = 0x11;

		/* Max Response Time: 10.0 sec */
		packet[35] = 100;

		/* Checksum: to be filled in */
		packet[36] = 0x00;
		packet[37] = 0x00;

		/* Group Address: zeroed for General Query */
		packet[38] = 0x00;
		packet[39] = 0x00;
		packet[40] = 0x00;
		packet[41] = 0x00;

		computeAndStoreIpChecksum((u_short *) &packet[34], 8 / 2, (u_short *) &packet[36]);
	}

	/* Trailer: 000055555555555555555555555555555555 */
	{
		packet[42] = 0x00;
		packet[43] = 0x00;
		packet[44] = 0x55;
		packet[45] = 0x55;
		packet[46] = 0x55;
		packet[47] = 0x55;
		packet[48] = 0x55;
		packet[49] = 0x55;
		packet[50] = 0x55;
		packet[51] = 0x55;
		packet[52] = 0x55;
		packet[53] = 0x55;
		packet[54] = 0x55;
		packet[55] = 0x55;
		packet[56] = 0x55;
		packet[57] = 0x55;
		packet[58] = 0x55;
		packet[59] = 0x55;
	}

	n = 60;	/* number of bytes to transmit */

	/* Send down the packet */
	if (pcap_sendpacket(fp,	// Adapter
		packet,				// buffer with the packet
		n					// size
		) != 0)
	{
		fprintf(stderr, "Error sending the IGMP query: %s\n\n", pcap_geterr(fp));
		return 3;
	}
	else
	{
		printf("IGMPv2 general query %s --> %s\n\n", iptos(src_addr), iptos(dst_addr));
	}

	pcap_close(fp);	

	return 0;
}

/* Step thru available devices and transmit an IGMPv2 query on all active IPv4 interfaces */
int main(int argc, char **argv) {
	pcap_if_t *alldevs;
	pcap_if_t *d;
	u_char ttl;
	char *basename;
	char dst_addr[64];
	char errbuf[PCAP_ERRBUF_SIZE + 1];

	strcpy_s(dst_addr, sizeof (dst_addr), "224.0.0.1");
	ttl = 1;

	printf("\nIGMPv2 query generator %s\n", VERSION_STR);
	printf("    Project web site: http://code.google.com/p/igmpquery/\n");
	printf("    Requires WinPcap\n\n");

	if (argc != 1) {
		basename = strrchr(argv[0], '/');
		if (basename == NULL) {
			basename = strrchr(argv[0], '\\');
		}
		if (basename == NULL) {
			basename = argv[0];
		} else {
			basename++;
		}
		printf("Usage: %s\n\n", basename);
	}

	/* Retrieve the interfaces list */
	if (pcap_findalldevs/*_ex*/(/*source, NULL,*/ &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n",errbuf);
		exit(1);
	}

	/* Scan the list printing connected entries */
	for (d = alldevs; d; d = d->next) {
		if (d) {
			if (d->addresses && (d->addresses->addr->sa_family == AF_INET)) {
				ifprint(d);
				igmpQuery(d->name,
					((struct sockaddr_in *) d->addresses->addr)->sin_addr.s_addr,
					inet_addr(dst_addr),
					ttl);
			}
		}
	}

	pcap_freealldevs(alldevs);

	return 1;
}

