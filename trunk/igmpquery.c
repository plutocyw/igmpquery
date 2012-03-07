/*
 * Copyright (c) 2010, Jim Hollinger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Jim Hollinger nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORSBE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
 * Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Politecnico di Torino, CACE Technologies 
 * nor the names of its contributors may be used to endorse or promote 
 * products derived from this software without specific prior written 
 * permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * This software is based on the WinPcap sendpack.c example program
 * and requires the WinPcap library: http://www.winpcap.org/.
 *
 */

/*
 * IGMP query generator
 *
 * Transmits a Internet Group Management Protocol (IGMP) v2 or v3
 * general query to all active IPv4 network interfaces.
 * Queries are sent to the all-hosts multicast group: 224.0.0.1.
 * All IGMP aware hosts that have joined a multicast group should respond.
 *
 */

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>

#ifndef WIN32
#  include <sys/socket.h>
#  include <netinet/in.h>
#else
#  include <winsock.h>
#endif

#define VERSION_STR  "V1.4"

#pragma pack(1)

/* 4 byte IPv4 address */
typedef struct ipv4_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
} ipv4_address;

/* 6 byte MAC */
typedef struct mac_address {
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
    u_char byte5;
    u_char byte6;
} mac_address;

/* MAC header */
typedef struct mac_header {
    mac_address dmac;      /* Destination MAC */
    mac_address smac;      /* Source MAC */
    u_short ether_type;    /* Ether type */
} mac_header;

/* IPv4 header */
typedef struct ip_header {
    u_char  ver_ihl;        /* Version (4 bits) + Internet header length (4 bits) */
    u_char  tos;            /* Type of service */
    u_short tlen;           /* Total length */
    u_short identification; /* Identification */
    u_short flags_fo;       /* Flags (3 bits) + Fragment offset (13 bits) */
    u_char  ttl;            /* Time to live */
    u_char  proto;          /* Protocol */
    u_short crc;            /* Header checksum */
    u_long  saddr;          /* Source address */
    u_long  daddr;          /* Destination address */
    u_int   op_pad;         /* Option + Padding */
} ip_header;

/* ARP header */
typedef struct arp_header {
    u_short htype;          /* Hardware type */
    u_short ptype;          /* Protocol type */
    u_char  hlen;           /* Hardware address length */
    u_char  plen;           /* Protocol address length */
    u_short oper;           /* Operation */
    mac_address  sha;       /* Sender hardware address */
    u_long  spa;            /* Sender protocol address */
    mac_address  tha;       /* Target hardware address */
    u_long  tpa;            /* Target protocol address */
} arp_header;

/* ICMP header */
typedef struct icmp_header {
    u_char  type;           /* Type */
    u_char  code;           /* Code */
    u_short crc;            /* Checksum */
    u_short id;             /* ID */
    u_short seq;            /* Sequence */
} icmp_header;

/* IGMP header */
typedef struct igmp_header {
    u_char  type;           /* Type */
    u_char  mrt;            /* Max response time */
    u_short crc;            /* Checksum */
    u_long  gaddr;          /* Group address */
} igmp_header;

/* TCP header */
typedef struct tcp_header {
    u_short sport;          /* Source port */
    u_short dport;          /* Destination port */
    u_int   seq_num;        /* Sequence number*/
    u_int   ack_num;        /* Acknowledgment number*/
    u_char  offset;         /* Data offset */
    u_char  flags;          /* Flags */
    u_short window;         /* Window size */
    u_short crc;            /* Checksum */
    u_short urgent;         /* Urgent pointer */
} tcp_header;

/* UDP header */
typedef struct udp_header {
    u_short sport;          /* Source port */
    u_short dport;          /* Destination port */
    u_short len;            /* Datagram length */
    u_short crc;            /* Checksum */
} udp_header;

/* IPv4 protocols */
enum ipv4_proto {
    HOPOPT      =  0,
    ICMP        =  1,
    IGMP        =  2,
    GGP         =  3,
    IP          =  4,
    ST          =  5,
    TCP         =  6,
    CBT         =  7,
    EGP         =  8,
    IGP         =  9,
    BBN_RCC_MON = 10,
    NVP_II      = 11,
    PUP         = 12,
    ARGUS       = 13,
    EMCON       = 14,
    XNET        = 15,
    CHAOS       = 16,
    UDP         = 17,
    MUX         = 18,
    DCN_MEAS    = 19,
    HMP         = 20,
    PRM         = 21,
    XNS_IDP     = 22
} ipv4_proto;

/* IPv4 protocols */
enum igmp_type {
    IGMP_QUERY      = 0x11,
    IGMPv1_REPORT   = 0x12,
    IGMPv2_REPORT   = 0x16,
    IGMP_LEAVE      = 0x17,
    IGMPv3_REPORT   = 0x22,
} igmp_type;

/* Return string representation of IPv4 protocol */
const char *ipv4ProtoToString(u_char proto) {
    const char *str = "UNKNOWN-PROTO";

    switch (proto) {

    case HOPOPT:       str = "HOPOPT";       break;
    case ICMP:         str = "ICMP";         break;
    case IGMP:         str = "IGMP";         break;
    case GGP:          str = "GGP";          break;
    case IP:           str = "IP";           break;
    case ST:           str = "ST";           break;
    case TCP:          str = "TCP";          break;
    case CBT:          str = "CBT";          break;
    case EGP:          str = "EGP";          break;
    case IGP:          str = "IGP";          break;
    case BBN_RCC_MON:  str = "BBN-RCC-MON";  break;
    case NVP_II:       str = "NVP-II";       break;
    case PUP:          str = "PUP";          break;
    case ARGUS:        str = "ARGUS";        break;
    case EMCON:        str = "EMCON";        break;
    case XNET:         str = "XNET";         break;
    case CHAOS:        str = "CHAOS";        break;
    case UDP:          str = "UDP";          break;
    case MUX:          str = "MUX";          break;
    case DCN_MEAS:     str = "DCN-MEAS";     break;
    case HMP:          str = "HMP";          break;
    case PRM:          str = "PRM";          break;
    case XNS_IDP:      str = "XNS-IDP";      break;
    default:  break;

    }

    return str;
}


/* Return string representation of ICMP code */
const char *icmpCodeToString(u_char code) {
    const char *str = "UNKNOWN-ICMP-CODE";

    switch (code) {

    case  0:           str = "Echo Reply";               break;
    case  1:           str = "Reserved";                 break;
    case  2:           str = "Reserved";                 break;
    case  3:           str = "Destination Unreachable";  break;
    case  4:           str = "Source Quench";            break;
    case  5:           str = "Redirect Message";         break;
    case  6:           str = "Alternate Address";        break;
    case  7:           str = "Reserved";                 break;
    case  8:           str = "Echo Request";             break;
    case  9:           str = "Router Advertisement";     break;
    case 10:           str = "Router Solicitation";      break;
    case 11:           str = "Time Exceeded";            break;
    case 12:           str = "Bad Parameter";            break;
    case 13:           str = "Timestamp";                break;
    case 14:           str = "Timestamp Reply";          break;
    case 15:           str = "Information Request";      break;
    case 16:           str = "Informatiob Reply";        break;
    case 17:           str = "Address Mask Request";     break;
    case 18:           str = "Address Mask Reply";       break;
    case 19:           str = "HOPOPT";                   break;
    case 30:           str = "Traceroute";               break;
    default:  break;

    }

    return str;
}


/* Return string representation of IGMP type */
const char *igmpTypeToString(u_char type) {
    const char *str = "UNKNOWN-IGMP-TYPE";

    switch (type) {

    case IGMP_QUERY:    str = "Query";                   break;
    case IGMPv1_REPORT: str = "v1 Rpt";                  break;
    case IGMPv2_REPORT: str = "Rpt";                     break;
    case IGMP_LEAVE:    str = "Leave";                   break;
    case IGMPv3_REPORT: str = "v3 Rpt";                  break;
    default:  break;

    }

    return str;
}


/* Return string representation of ARP operation */
const char *arpOperToString(u_short oper) {
    const char *str = "UNKNOWN-OPER";

    switch (oper) {

    case 1:            str = "Request";                  break;
    case 2:            str = "Reply";                    break;
    default:  break;

    }

    return str;
}


/* Convert a numeric IPv4 address to a string */
#define IPTOSBUFFERS    (12)
char *ip4ToString(u_long in) {
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
char *ip6ToString(struct sockaddr *sockaddr, char *address, int addrlen) {
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


/* Print an ip address */
void ip_addr_print(pcap_addr_t *a) {
    char ip6str[128];

    switch (a->addr->sa_family) {

    case AF_INET:
        if (a->addr)
            printf("    Address: %s\n",
                ip4ToString(((struct sockaddr_in *) a->addr)->sin_addr.s_addr));
        break;

    case AF_INET6:
        if (a->addr)
            printf("    Address: %s\n", ip6ToString(a->addr, ip6str, sizeof (ip6str)));
        break;

    default:
        break;
    }
}


/* Print all the available information for an ip address */
void ip_print(pcap_addr_t *a) {
    switch (a->addr->sa_family) {

    case AF_INET:
        printf("    Address Family Name: AF_INET\n");
        ip_addr_print(a);
        if (a->netmask)
            printf("    Netmask: %s\n",
                ip4ToString(((struct sockaddr_in *) a->netmask)->sin_addr.s_addr));
        if (a->broadaddr)
            printf("    Broadcast Address: %s\n",
                ip4ToString(((struct sockaddr_in *) a->broadaddr)->sin_addr.s_addr));
        if (a->dstaddr)
            printf("    Destination Address: %s\n",
                ip4ToString(((struct sockaddr_in *) a->dstaddr)->sin_addr.s_addr));
        break;

    case AF_INET6:
        printf("    Address Family Name: AF_INET6\n");
        ip_addr_print(a);
        break;

    default:
        printf("    Address Family Name: Unknown\n");
        break;
    }
}


/* Print information on the given interface */
void if_print(pcap_if_t *d) {

    /* Name */
    printf("%s\n", d->name);

    /* Description */
    if (d->description) {
        printf("    Description: %s\n", d->description);
    }

    /* Loopback Address*/
    if (d->flags) {
        printf("    Loopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");
    }

    printf("\n");
}


/* Print packet details */
void packet_print(const u_char *pkt_data) {
    u_short ether_type;
    struct mac_header  *mac;
    struct ip_header   *ip;
    struct icmp_header *icmp;
    struct igmp_header *igmp;
    struct tcp_header  *tcp;
    struct udp_header  *udp;
    struct arp_header  *arp;
    u_int  mac_len;
    u_int  ip_len;

    mac = (mac_header *) pkt_data;
    mac_len = sizeof (mac_header);
    ether_type = ntohs(mac->ether_type);
    switch (ether_type) {

    case 0x0800:  /* IPv4 */

        /* retireve the position of the ip header */
        ip = (ip_header *) (pkt_data + mac_len);
        ip_len = (ip->ver_ihl & 0x0F) * 4;

        switch (ip->proto) {

        case ICMP:
            icmp = (icmp_header *) (pkt_data + mac_len + ip_len);
            printf("%14s      ->%14s       ",
                ip4ToString(ip->saddr),
                ip4ToString(ip->daddr));
            printf("%4s %s\n", ipv4ProtoToString(ip->proto), icmpCodeToString(icmp->type));
            break;

        case IGMP:
            igmp = (igmp_header *) (pkt_data + mac_len + ip_len);
            printf("%14s      ->%14s       ",
                ip4ToString(ip->saddr),
                ip4ToString(ip->daddr));
            if ((igmp->type == IGMP_QUERY) && (igmp->gaddr == 0)) {
                printf("%4s %s %s\n", ipv4ProtoToString(ip->proto), igmpTypeToString(igmp->type),
                    "General");
            } else {
                printf("%4s %s %s\n", ipv4ProtoToString(ip->proto), igmpTypeToString(igmp->type),
                    ip4ToString(igmp->gaddr));
            }
            break;

        case TCP:
            tcp = (tcp_header *) (pkt_data + mac_len + ip_len);
            printf("%14s:%-5u->%14s:%-5u ",
                ip4ToString(ip->saddr), ntohs(tcp->sport),
                ip4ToString(ip->daddr), ntohs(tcp->dport));
            printf("%4s\n", ipv4ProtoToString(ip->proto));
            break;

        case UDP:
            udp = (udp_header *) (pkt_data + mac_len + ip_len);
            printf("%14s:%-5u->%14s:%-5u ",
                ip4ToString(ip->saddr), ntohs(udp->sport),
                ip4ToString(ip->daddr), ntohs(udp->dport));
            printf("%4s Len: %u\n", ipv4ProtoToString(ip->proto), ntohs(udp->len));
            break;

        default:
            printf("%14s      ->%14s       ",
                ip4ToString(ip->saddr),
                ip4ToString(ip->daddr));
            printf("%4s\n", ipv4ProtoToString(ip->proto));
            break;
        }
        break;

    case 0x0806:  /* ARP */

        /* retireve the position of the arp header */
        arp = (arp_header *) (pkt_data + mac_len); 
        printf("%14s      ->%14s       ",
            ip4ToString(arp->spa),
            ip4ToString(arp->tpa));
        printf("%4s %s\n", "ARP", arpOperToString(ntohs(arp->oper)));
        break;

    case 0x888E:  /* EAP */
        printf("%4s\n", "EAP");
        break;

    default:
        printf("Ether Type 0x%04X\n", ether_type);
        break;
    }
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


/* Transmit an IGMP general query */
int igmpQuery(pcap_t *fp, u_long src_addr, u_long dst_addr, u_char ttl, u_char response_time, int version) {
    u_char packet[128];
    int n;

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
        packet[14] = (4 << 4) | (24 / 4);

        /* Differentiated Services: 0x00 */
        packet[15] = 0x00;

        /* Total Length: MAC header length + IP header length */
        packet[16] = 0;
        
        if (version == 3) {
            packet[17] = 24 + 12;
        } else {
            packet[17] = 24 + 8;
        }
        
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

        packet[34] = 0x94;
        packet[35] = 0x04;
        packet[36] = 0x00;
        packet[37] = 0x00;

        computeAndStoreIpChecksum((u_short *) &packet[14], 24 / 2, (u_short *) &packet[24]);
    }

    /* IGMP packet */
    {
        /* Type: Membership Query */
        packet[38] = IGMP_QUERY;

        /* Max Response Time */
        packet[39] = response_time * 10;

        /* Checksum: to be filled in */
        packet[40] = 0x00;
        packet[41] = 0x00;

        /* Group Address: zeroed for General Query */
        packet[42] = 0x00;
        packet[43] = 0x00;
        packet[44] = 0x00;
        packet[45] = 0x00;

        if(version == 3) {

            /*IGMPv3 */
            packet[46] = 0x00;
            packet[47] = 0x0a;
            packet[48] = 0x00;
            packet[49] = 0x00;

            computeAndStoreIpChecksum((u_short *) &packet[38], 12 / 2, (u_short *) &packet[40]);

        } else {
            computeAndStoreIpChecksum((u_short *) &packet[38], 8 / 2, (u_short *) &packet[40]);
            
            /* IGMPv2*/
            packet[46] = 0x00;
            packet[47] = 0x00;
            packet[48] = 0x55;
            packet[49] = 0x55;	
        }

    }

    /* Trailer: 000055555555555555555555555555555555 */
    {
        packet[50] = 0x00;
        packet[51] = 0x00;
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
    if (pcap_sendpacket(fp,	/* Adapter */
        packet,				/* buffer with the packet */
        n					/* size */
        ) != 0)
    {
        fprintf(stderr, "Error sending the IGMP query: %s\n\n", pcap_geterr(fp));
        return -1;
    }
    else
    {
        if (version == 3) {
            printf("IGMPv3");
        } else {
            printf("IGMPv2");
        }
        printf(" general query %s -> %s\n\n", ip4ToString(src_addr), ip4ToString(dst_addr));
        
    }

    return 0;
}


/* Listen for traffic on the interface that passes the filter */
void pcapListen(pcap_t *fp, u_char listen_s) {
    struct pcap_pkthdr *header;
    const u_char       *pkt_data;
    char                time_str[16];
    struct tm           ltime;
    time_t              local_s, start_s, now_s;
    double              elapse_s;
    int                 res;

    /* Retrieve the packets */
    time(&start_s);
    while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0) {

        if (res == 0) {  /* Timeout elapsed */
            time(&now_s);
            elapse_s = difftime(now_s, start_s);
            if (elapse_s >= listen_s) {
                break;
            } else {
                continue;
            }
        }
        
        /* convert the timestamp to readable format */
        local_s = header->ts.tv_sec;
        localtime_s(&ltime, &local_s);
        strftime(time_str, sizeof (time_str), "%H:%M:%S", &ltime);
        
        printf("%s.%.03d ", time_str, header->ts.tv_usec / 1000);
        packet_print(pkt_data);
    }
}


/* Step thru available devices and transmit an IGMPv2 query on all active IPv4 interfaces */
int main(int argc, char **argv) {
    pcap_if_t *alldevs = NULL;
    pcap_if_t *d = NULL;
    pcap_addr_t *a = NULL;
    pcap_t    *fp = NULL;
    struct bpf_program fcode;
    u_char     ttl = 0;
    u_char     response_s = 0;
    u_char     listen_s = 0;
    u_char     timeout_s = 0;
    u_int      netmask = 0;
    char       dst_addr[64];
    char       errbuf[PCAP_ERRBUF_SIZE + 1];
    char       packet_filter[] = "igmp";
    int        count = 0;
    int        just_list = 0;
    int        quiet = 0;
    int        dr = 0;
    int        ad = 0;
    int        specific = 0;
    int        driver = 0;
    int        address = 0;
    int        igmp_version = 0;
    strcpy_s(dst_addr, sizeof (dst_addr), "224.0.0.1");
    igmp_version = 2;
    ttl          = 1;
    response_s   = 1;
    listen_s     = 10;
    timeout_s    = 1;

    for (count = 1; count < argc; count++) {

        /* Check for a switch (leading "-") */
        if (argv[count][0] == '-') {

            /* Use the next character to decide what to do */
            switch (argv[count][1]) {

            case 'l':
                just_list = 1;
                break;

            case 'q':
                quiet = 1;
                break;

            case 'i':
                if ((count + 1) < argc) {
                    dr = atoi(argv[++count]);
                    if ((count + 1) < argc) {
                        ad = atoi(argv[++count]);
                    }
                }
                specific = 1;
                printf("\n Only run on Interface %d and Address %d\n\n", dr, ad);
                break;

            case 'v':
                igmp_version = 3; 
                break;

            default:
                printf("USAGE:\n");
                printf("  -l  list interfaces only, used when you want to find out the Interface and Address numbers\n");
                printf("  -q  quiet: stops the listing of the interfaces\n");
                printf("  -i  [Interface] [Address] just send IGMP on the interface specified eg -i 1 2\n");
                printf("  -v  forces a IGMPv3 query message\n\n");
                exit(2);
            }
        }
    }
    if (quiet != 1) {
        printf("\nIGMP query generator %s\n", VERSION_STR);
        printf("    Project web site: http://code.google.com/p/igmpquery/\n");
        printf("    Requires WinPcap\n\n");
    }
    
    /* Retrieve the interfaces list */
    if (pcap_findalldevs/*_ex*/(/*source, NULL,*/ &alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }
    if (alldevs == NULL) {
        fprintf(stderr, "Could not start pcap driver, try running as administrator\n");
        exit(1);
    }
    
    
    if (just_list == 1) {

        /* Just print the names of the interfaces and the number */
        driver = 1;
        for (d = alldevs; d; d = d->next, driver++) {
            if (d != NULL) {

                /* scan the addresses on the interface there could be more than one especially if IPv6 is on */
                address = 1;
                for (a = d->addresses; a; a = a->next, address++) {
                    if ((a != NULL) && (a->addr->sa_family == AF_INET)) {

                        if (d->description) {
                            printf("Interface %d and Address %d  Description: %s\n", driver, address,d->description);
                            ip_addr_print(a);
                        }
                    }
                }
            }
        }
        return 1;
    }

    /* Scan the list printing connected entries */
    driver = 1;
    for (d = alldevs; d; d = d->next, driver++) {
        if (d != NULL) {
            if (quiet != 1) {
                if_print(d);
            }

            /* Scan the addresses on the interface, there could be more than one especially if IPv6 is on */
            address = 1;
            for (a = d->addresses; a; a = a->next, address++) {
                if ((a != NULL) && (a->addr->sa_family == AF_INET)) {
                    if (quiet != 1) {
                        ip_print(a);
                    }
                    if (specific && ((driver != dr) || (address != ad))) {
                        if (quiet != 1) {
                            printf("Interface and Address do not a match\n\n");
                        }
                        continue;
                    }
                    /* Open the adapter */
                    if ((fp = pcap_open_live(d->name,	/* name of the device */
                        65536,							/* portion of the packet to capture. It doesn't matter in this case */
                        1,								/* promiscuous mode (nonzero means promiscuous) */
                        timeout_s * 1000,				/* read timeout */
                        errbuf							/* error buffer */
                        )) == NULL)
                    {
                        fprintf(stderr, "Unable to open the adapter. %s is not supported by WinPcap.\n\n", d->name);
                    } else {

                        /* transmit IGMP query */
                        if (igmpQuery(fp,
                            ((struct sockaddr_in *) (a->addr))->sin_addr.s_addr,
                            inet_addr(dst_addr),
                            ttl,
                            response_s, igmp_version) >= 0) {

                            /* listen for responses */
                            if (pcap_datalink(fp) != DLT_EN10MB) {
                                fprintf(stderr,"\nNot an Ethernet network.\n");
                            } else {

                                /* Retrieve the mask of the first address of the interface */
                                netmask = ((struct sockaddr_in *) (a->netmask))->sin_addr.s_addr;

                                /* compile the filter */
                                if (pcap_compile(fp, &fcode, packet_filter, 1, netmask) < 0) {
                                    fprintf(stderr, "\nUnable to compile the packet filter. Check the syntax.\n");
                                } else {
                                
                                    /* Set the filter */
                                    if (pcap_setfilter(fp, &fcode) < 0) {
                                        fprintf(stderr, "\nError setting the filter.\n");
                                    } else {

                                        /* listen for responses */
                                        printf("listening for responses ...\n");
                                        pcapListen(fp, listen_s);
                                        printf("\n\n");
                                    }
                                }
                            }
                        }
                        pcap_close(fp);
                        fp = NULL;
                    }
                }
            }
        }
    }

    pcap_freealldevs(alldevs);

    return 1;
}

