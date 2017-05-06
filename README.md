# igmpquery
Originally exported from [Google Code](https://code.google.com/archive/p/igmpquery/)

Patched to work on Linux and add support for IGMPv1

Depends on: 
  [libpcap](http://www.tcpdump.org/#latest-release)

Build instruction:
  `gcc ./igmpquery.c -I./libpcap-1.7.4 -L./libpcap-1.7.4 -lpcap -o igmpquery`
