# DataplaneRouter

For the implementation of the router, I used the following workflow:

## Route Table & Routing Process
I initialized the static routing table, which I sorted using `qsort` with a comparison function that sorts based on the conditions for Longest Prefix Match (LPM). In case of equality, it is sorted in ascending order by mask. I chose to sort the table because, to find the best route, I implemented a binary search with a complexity of O(log n), which is much more efficient than a linear search.

## ARP
I initialized the ARP table. For the implementation of the ARP protocol, I followed these steps:
- When the router receives an ARP REQUEST with one of its interface IP addresses, it sends an ARP REPLY with the corresponding MAC address of the interface.
- When an ARP REPLY is received, the ARP table is updated if the MAC address is not found in the ARP table. After this, it checks if there are any packets in the queue. If so, they are processed, and if all necessary information is available (such as source IP, destination IP, source MAC, destination MAC), the processing and sending of the respective packet continues.

## IP ICMP
When a packet is received on one of the interfaces, it first checks if the packet is an ICMP echo destined for the router, in which case an ICMP echo reply is sent back to the sender of that packet. Next, the checksum is verified, and if it is incorrect, the packet is dropped. Then, the TTL (Time to Live) is checked, and if it has reached zero, an ICMP time exceeded message is sent. The router searches the routing table for the best route, and if it does not exist, it sends an ICMP destination unreachable message. The TTL is decremented, and the checksum is updated. 

Next, the Ethernet header is modified with the destination MAC address found in the ARP table. If the MAC address does not exist in the ARP table, the packet is queued, and an ARP REQUEST is made to discover the corresponding MAC address. If the MAC address is found in the ARP table, the Ethernet header is updated accordingly for forwarding the packet with the destination MAC address and the router's MAC address.
