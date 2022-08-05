#ifndef _ARP_IP_ICMP_H_
#define _ARP_IP_ICMP_H_

// The compare function used for Quick sort in order to sort the routing table
// in descending order of the prefixes and in case of the same prefix, in descending
// order of the masks
int compareFunction 
(const void *firstEntry, const void *secondEntry);

// The function that does a binary search in the routing table and returns the best route for a given IP
struct route_table_entry *get_best_routeBinarySearch 
(struct in_addr dest_ip, int rtable_len, struct route_table_entry *rtable, int left, int right);

// The function that does a linear search in the routing table and returns the best route for a given IP
struct route_table_entry *get_best_route 
(struct in_addr dest_ip, int rtable_len, struct route_table_entry *rtable);

// The function that checks if an IP is in the ARP Cache and if it is, it returns
// the coresponding MAC of that address
uint8_t *arpCacheContainsEntry 
(struct arp_entry table[], uint32_t ipAddress, int length);

// The function that checks whether a packet is for the router or not
int checkIfMacIsForRouter 
(struct ether_header *packetEtherHeader, uint8_t myMac[6]);

// The function that constructs an ICMP packet when the router has the send an
// "destination unreachable" or an "time exceeded" message
packet *constructIcmpPacket 
(packet receivedPacket, uint8_t type, uint8_t code);

// The function that checks if when we receive and ARP Reply, we got the MAC
// of the next hop for one packet that was in the queue 
int nextHopMatches 
(packet *currentPacket, struct route_table_entry *rtable, 
int rtable_len, struct arp_entry arpTable[], int arpTableLength);

// The RFC 1624 function-formula to update the checksum when changing just the TTL
uint16_t updateIpChecksum
(uint16_t oldChecksum, uint16_t oldTtl, uint16_t newTtl);

#endif /*_ARP_IP_ICMP_H_*/