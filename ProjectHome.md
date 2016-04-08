A simple utility for generating an [IGMP](http://en.wikipedia.org/wiki/Internet_Group_Management_Protocol) general query on all active IPv4 interfaces and then listening for responses.

Uses the [WinPcap](http://www.winpcap.org/) library for raw socket access.

A Windows binary executable is available for download as well as the C source code.

Example console output:
```
IGMPv2 query generator V1.2
    Project web site: http://code.google.com/p/igmpquery/
    Requires WinPcap

\Device\NPF_{xxxx}
    Description: Intel(R) WiFi Link 5300 AGN (Microsoft's Packet Scheduler)
    Address Family: #2
    Address Family Name: AF_INET
    Address: 10.18.0.41
    Netmask: 255.255.255.0
    Broadcast Address: 255.255.255.255

IGMPv2 general query 10.18.0.41 -> 224.0.0.1

listening for responses ...
15:02:14.084     10.18.0.42      ->     224.1.0.1       IGMP Rpt 224.1.0.1
15:02:14.084     10.18.0.42      ->     224.1.0.2       IGMP Rpt 224.1.0.2
15:02:14.084     10.18.0.43      ->   224.0.6.164       IGMP Rpt 224.0.6.164
15:02:14.084     10.18.0.43      ->   224.0.6.196       IGMP Rpt 224.0.6.196
```