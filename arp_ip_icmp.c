#include "skel.h"

int compareFunction 
(const void *firstEntry, const void *secondEntry) {
	if (((struct route_table_entry *) firstEntry)->prefix 
    < ((struct route_table_entry *) secondEntry)->prefix) {

		return 1;
	} else if (((struct route_table_entry *) firstEntry)->prefix 
    > ((struct route_table_entry *) secondEntry)->prefix) {

		return -1;
	} else {
		if (((struct route_table_entry *) firstEntry)->mask 
        < ((struct route_table_entry *) secondEntry)->mask) {

			return 1;
		} else if (((struct route_table_entry *) firstEntry)->mask 
        > ((struct route_table_entry *) secondEntry)->mask) {

			return -1;
		} else {
			return 0;
		}
	}
}

struct route_table_entry *get_best_routeBinarySearch 
(struct in_addr dest_ip, int rtable_len, struct route_table_entry *rtable, int left, int right) {
	if (right >= left) {
		int mid = left + ((right - left) / 2);

		// We found the prefix, now we have to find out whether it 
		// exists a bigger mask to the left of the table or not
		// as the table was sorted in descending order
		if ((dest_ip.s_addr & rtable[mid].mask) == rtable[mid].prefix) {
			int index = mid;

			for (int i = mid - 1; i >= 0 
            && ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix);  i--) {
                
				index = i;
			}

			return &rtable[index];

		} else if ((dest_ip.s_addr & rtable[mid].mask) > rtable[mid].prefix) {
			return get_best_routeBinarySearch(dest_ip, rtable_len, rtable, left, mid - 1);
		} else {
			return get_best_routeBinarySearch(dest_ip, rtable_len, rtable, mid + 1, right);
		}

	}

	return NULL;
}

struct route_table_entry *get_best_route (struct in_addr dest_ip,
 int rtable_len, struct route_table_entry *rtable) {
	size_t index = -1;

    // We iterate through the hole routing table and we choose
    // the prefix that matches our IP with the longest mask
	for (int i = 0; i < rtable_len; i++) {
		if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {
			if (index == -1) {
				index = i;
			} else if (ntohl(rtable[index].mask) < ntohl(rtable[i].mask)) {
				index = i;
			}
		}
	}

	if (index == -1) {
		return NULL;
	} else {
		return &rtable[index];
	}

}

uint8_t *arpCacheContainsEntry (struct arp_entry table[], uint32_t ipAddress, int length) {
    // We iterate through the hole ARP cache and if we find
    // the IP we search for, we return the coresponding mac
	for (int i = 0; i < length; i++) {
		if (table[i].ip == ipAddress) {
			return table[i].mac;
		}
	}

	return NULL;
}

int checkIfMacIsForRouter (struct ether_header *packetEtherHeader, uint8_t myMac[6]) {
    // Check if the mac of the router's interface
    // is the same with the mac of the packet
	int macMatches = 1;
	for (int i = 0; i <= 5; i++) {
		if (myMac[i] != packetEtherHeader->ether_dhost[i]) {
			macMatches = 0;
			break;
		}
	}

    // Check if the mac of the packet is broadcast
	if (macMatches == 0) {
		macMatches = 1;
		for (int i = 0; i <= 5; i++) {
			if (packetEtherHeader->ether_dhost[i] != 0xFF) {
				macMatches = 0;
				break;
			}
		}
	}

	return macMatches;
}


packet *constructIcmpPacket (packet receivedPacket, uint8_t type, uint8_t code) {
	struct ether_header *etherHeader = (struct ether_header *)receivedPacket.payload;
	struct iphdr *ipHeader = (struct iphdr *)(((void *)etherHeader) + sizeof(struct ether_header));
	struct icmphdr icmpHeader;

	packet *icmpPacket = (packet *)malloc(sizeof(packet));

	uint8_t destinationMacAddress[6];

    // We construct the ethernet header as opposite to the one
    // that came to the router
	memcpy(destinationMacAddress, etherHeader->ether_dhost, 6);
	memcpy(etherHeader->ether_dhost, etherHeader->ether_shost, 6);
	memcpy(etherHeader->ether_shost, destinationMacAddress, 6);

    // We construct the IP header such that we have an ICMP after/over it
	ipHeader->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
	ipHeader->ttl = 64;
	ipHeader->protocol = 1;
	ipHeader->id = htons(1);

	uint32_t destinationIpAddress;

	destinationIpAddress = ipHeader->daddr;
	ipHeader->daddr = ipHeader->saddr;
	ipHeader->saddr = destinationIpAddress;

    // We recalculate the checksum for the IP header because we changed
    // some fields
	ipHeader->check = 0;
	ipHeader->check = ip_checksum((void *) ipHeader, sizeof(struct iphdr));

    // We construct the coresponding ICMP and calculate it's checksum
	icmpHeader.type = type;
	icmpHeader.code = code;
	icmpHeader.checksum = 0;
	icmpHeader.checksum = icmp_checksum((uint16_t *) &icmpHeader, sizeof(struct icmphdr));

    // We construct the packet and we return it ready to be delivered
	void *payload = icmpPacket->payload;
	memcpy(payload, etherHeader, sizeof(struct ether_header));
	payload += sizeof(struct ether_header);
	memcpy(payload, ipHeader, sizeof(struct iphdr));
	payload += sizeof(struct iphdr);
	memcpy(payload, &icmpHeader, sizeof(struct icmphdr));
	payload += sizeof(struct icmphdr);

	memcpy(payload, (((void *)ipHeader) + sizeof(struct iphdr)), 64);

	icmpPacket->len = sizeof(struct ether_header) 
    + sizeof(struct iphdr) + sizeof(struct icmphdr) + 64;

	return icmpPacket;
}

int nextHopMatches (packet *currentPacket, struct route_table_entry *rtable,
 int rtable_len, struct arp_entry arpTable[], int arpTableLength) {

	struct ether_header *etherHeader = (struct ether_header *)currentPacket->payload;
	struct iphdr *ipHeader = (struct iphdr *)(((void *)etherHeader) + sizeof(struct ether_header));
	
	struct in_addr destinationAddress; 
	destinationAddress.s_addr = ipHeader->daddr;

    // We get the best route for the current IP address
	struct route_table_entry *route = get_best_route(destinationAddress, rtable_len, rtable);

    // We check if the next hop of the given route exists in the ARP cache or not
	if (arpCacheContainsEntry(arpTable, route->next_hop, arpTableLength) != NULL) {
		memcpy(etherHeader->ether_dhost, arpCacheContainsEntry(arpTable, route->next_hop, arpTableLength), 6);
		return 1;
	}

	return 0;
}

uint16_t updateIpChecksum(uint16_t oldChecksum, uint16_t oldTtl, uint16_t newTtl) {
	return ~(~oldChecksum + ~oldTtl + newTtl) - 1;
}