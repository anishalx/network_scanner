"""NetScanner - fast, cross-platform network discovery and port scanning.

Methods:
  * arp  - Layer-2 host discovery on the local segment (requires admin/root)
  * ping - Layer-3 ICMP echo sweep (requires raw sockets / admin on most OSes)
  * tcp  - Privilege-free TCP connect port scan
  * udp  - Privilege-free UDP datagram scan (open / open|filtered detection)
  * all  - Auto: ARP -> ICMP -> TCP common-port fallback
"""

__version__ = "2.0.0"
