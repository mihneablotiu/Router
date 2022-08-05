#include "queue.h"
#include "skel.h"
#include "arp_ip_icmp.h"

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// We initialise and we sort our routing table for the router
	struct route_table_entry *rtable = malloc(sizeof(struct route_table_entry) * 100000);
	DIE(!rtable, "Memory error");
	int rtable_len = read_rtable(argv[1], rtable);
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compareFunction);

	// We initialise the queue used to store the packets that are wating
	// for an MAC address so were not yet sent
	queue routerQueue = queue_create();

	// Our ARP cache made with an arp_entry vector
	struct arp_entry arpTable[20];
	int arpTableLength = 0;

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// Check if the packet is shorter than it should be and drop it in
		// affirmative case
		if (m.len < sizeof(struct ether_header)) {
			fprintf(stderr, "%s\n", "Too short packet");
			continue;
		}

		// The interface on which the packet got to the router
		uint8_t myInterfaceMac[6];
		get_interface_mac(m.interface, myInterfaceMac);

		// The Ethernet header of the packet the router received
		struct ether_header *etherHeader = (struct ether_header *)m.payload;

		// Firstly we make the Layer 2 verification -> whether the packet is
		// for the router or not (checking the interface that the packet got
		// to the router with the MAC address it was trageted to)
		int macMatches = checkIfMacIsForRouter(etherHeader, myInterfaceMac);

		// If the packet is for the router, check which type of packet it is
		if (macMatches == 1) {
			// Check whether the packet is ARP or not
			if (ntohs(etherHeader->ether_type) == 0x806) {
				// The ARP header that follows the Ethernet header 
				struct arp_header *arpHeader 
				= (struct arp_header *)(((void *)etherHeader) + sizeof(struct ether_header));

				// Check whether the packet is an ARP Request for the router
				// If it is, we are going to send a reply
				if (ntohs(arpHeader->op) == 1) {
					// We prepare the reply for the ARP Request
					arpHeader->op = htons(2);

					// We swap the destination with the sender IPv4 addresses because the
					// the reply is exactly the opposite of a request
					uint32_t destinationIp;
					destinationIp = arpHeader->spa;
					arpHeader->spa = arpHeader->tpa;
					arpHeader->tpa = destinationIp;

					// We swap the destination with the sender MAC addresses because the
					// the reply is exactly the opposite of a request (we do this both)
					// in the ARP Header and in the Ethernet Header.
					memcpy(arpHeader->tha, arpHeader->sha, 6);
					memcpy(arpHeader->sha, myInterfaceMac, 6);
					memcpy(etherHeader->ether_dhost, etherHeader->ether_shost, 6);
					memcpy(etherHeader->ether_shost, myInterfaceMac, 6);

					// The packet is ready and we send the reply
					send_packet(&m);
				
				// Check whether the packet is an ARP Replay for the older ARP
				// Request from router. If it is, we are going to add the reply
				// into our cache
				} else if (ntohs(arpHeader->op) == 2) {
					// We create the new entry that we are going to add in the cache
					struct arp_entry newEntry;

					// We set the IPv4 and the MAC addresses as the sender's
					newEntry.ip = arpHeader->spa;
					memcpy(newEntry.mac, arpHeader->sha, 6);

					// If the entry does not already exist in the ARP cache, we add it
					if (arpCacheContainsEntry(arpTable, newEntry.ip, arpTableLength) == NULL) {
						memcpy(&arpTable[arpTableLength], &newEntry, sizeof(struct arp_entry));
						arpTableLength++;

						// We iterate through the queue containing the packets that were waiting
						// just for the MAC address in order to be sent. We send those that just
						// received the MAC address and we create a new queue with those that
						// were not sent
						queue newQueue = queue_create();

						while (!queue_empty(routerQueue)) {
							packet *currentPacket = (packet *)queue_deq(routerQueue);

							// If we find a packet that received the MAC address right now, we send it
							if (nextHopMatches(currentPacket, rtable, rtable_len, arpTable, arpTableLength)) {
								send_packet(currentPacket);
							} else {
								queue_enq(newQueue, currentPacket);
							}
						}

						free(routerQueue);
						routerQueue = newQueue;
					}
				}

			// Check whether the received packet is an IP one
			} else if (ntohs(etherHeader->ether_type) == 0x0800) {
				// The IP header that follows the Ethernet header 
				struct iphdr *ipHeader = (struct iphdr *)(((void *)etherHeader) + sizeof(struct ether_header));

				// Check if the packet is an ICMP one and if it is addressed to the router
				if (ipHeader->protocol == 1 && ipHeader->daddr == inet_addr(get_interface_ip(m.interface))) {
					struct icmphdr *icmpHeader 
					= (struct icmphdr *)(((void *)ipHeader) + sizeof(struct iphdr));

					// Check is the packet it an echo request (type 8, code 0)
					// in afirmative case, we have to answer with an echo reply
					// (type 0, code 0)
					if (icmpHeader->type == 8 && icmpHeader->code == 0) {
						uint8_t destinationMacAddress[6];

						// We swap the destination with the sender MAC addresses because the
						// the reply is exactly the opposite of a request (we do this both)
						// in the IP Header and in the Ethernet Header.
						memcpy(destinationMacAddress, etherHeader->ether_dhost, 6);
						memcpy(etherHeader->ether_dhost, etherHeader->ether_shost, 6);
						memcpy(etherHeader->ether_shost, destinationMacAddress, 6);

						uint32_t destinationIpAddress = ipHeader->daddr;
						ipHeader->daddr = ipHeader->saddr;
						ipHeader->saddr = destinationIpAddress;

						// We recalculate the checksum as we changed some fields
						// such as the type of the ICMP
						ipHeader->check = 0;
						ipHeader->check = ip_checksum((void *) ipHeader, sizeof(struct iphdr));

						icmpHeader->type = 0;
						icmpHeader->checksum = 0;
						icmpHeader->checksum = icmp_checksum((uint16_t *) &icmpHeader, sizeof(struct icmphdr));

						// The ICMP reply is ready and we cand send it back to the
						// original source
						send_packet(&m);
						continue;
					}
				}

				// If the packet is not for the router, we check its checksum
				if (ip_checksum((void *) ipHeader, sizeof(struct iphdr)) != 0) {
					continue;
				}
				
				// We check the TTL and if it is not high enough we send and ICMP
				// and we drop the packet
				if (ipHeader->ttl == 1 || ipHeader->ttl == 0) {
					packet *icmpPacket = constructIcmpPacket(m, 11, 0);
					icmpPacket->interface = m.interface;
					send_packet(icmpPacket);
					continue;
				}

				struct in_addr destinationAddress; 

				destinationAddress.s_addr = ipHeader->daddr;

				// If the packet is good, we search the best route for it to forward it and if
				// the route does not exist, we send and ICMP and drop the packet
				struct route_table_entry *route = get_best_route(destinationAddress, rtable_len, rtable);
				if (route == NULL) {
					packet *icmpPacket = constructIcmpPacket(m, 3, 0);
					icmpPacket->interface = m.interface;
					send_packet(icmpPacket);
					continue;
				}

				// If we find the route, we update the TTL and the checksum with RFC 1624
				// as we modified just the TTL so we don't have to recalculate the hole checksum
				uint16_t oldTtl = ipHeader->ttl;
				uint16_t newTtl = oldTtl - 1;
				uint16_t oldCheckSum = ipHeader->check;

				ipHeader->ttl--;
				ipHeader->check = 0;
				ipHeader->check = updateIpChecksum(oldCheckSum, oldTtl, newTtl);
		
				// Now, the packet is ready, we just have to check if we have the MAC address of the
				// next hop in our cache. If we have it, we just update the ethernet header and
				// we send it. If we don't have it, we put the prepared packet in the queue
				// and we send an ARP Request for his MAC.
				if (arpCacheContainsEntry(arpTable, route->next_hop, arpTableLength) != NULL) {
					memcpy(etherHeader->ether_dhost, arpCacheContainsEntry(arpTable, route->next_hop, arpTableLength), 6);

					get_interface_mac(route->interface, etherHeader->ether_shost);
					m.interface = route->interface;

					send_packet(&m);
					continue;
				} else {
					get_interface_mac(route->interface, etherHeader->ether_shost);
					m.interface = route->interface;

					packet *queuePacket = (packet *)malloc(sizeof(packet));
					memcpy(queuePacket, &m, sizeof(packet));

					queue_enq(routerQueue, queuePacket);
				}

				packet arpRequest_nextHopMac;
				struct ether_header newEtherHeader;

				// We build the Ethernet header for and ARP broadcast request;
				newEtherHeader.ether_type = htons(0x806);

				for (int i = 0; i <= 5; i++) {
					newEtherHeader.ether_dhost[i] = 0xFF;
				}

				get_interface_mac(route->interface, newEtherHeader.ether_shost);

				struct arp_header newArpHeader;

				// We build the ARP header for and ARP broadcast request;
				newArpHeader.hlen = 6; // Length of the hardware address
				newArpHeader.htype = htons(1); // Type of the hardware address
				newArpHeader.ptype = htons(0x0800); // The type of the protocol address (IP)
				newArpHeader.plen = 4; // The length of the IP

				newArpHeader.op = htons(1); // It is a Request 

				// We update the ARP header addresses. The sender and receiver MAC
				// address are the same as in the Ethernet header, the IP sender address
				// is the one from the interface our best route shows, and the target
				// ip address is the next hop
				memcpy(newArpHeader.sha, newEtherHeader.ether_shost, 6);
				memcpy(newArpHeader.tha, newEtherHeader.ether_dhost, 6);
				newArpHeader.spa = inet_addr(get_interface_ip(route->interface));
				newArpHeader.tpa = route->next_hop;

				// We put those headers in the packet
				memset(arpRequest_nextHopMac.payload, 0, 1600);
				memcpy(arpRequest_nextHopMac.payload, &newEtherHeader, sizeof(struct ether_header));
				memcpy(arpRequest_nextHopMac.payload + sizeof(struct ether_header), &newArpHeader, sizeof(struct arp_header));

				// We set the length and the interface and then send the packet
				arpRequest_nextHopMac.len = sizeof(struct ether_header) + sizeof(struct arp_header);
				arpRequest_nextHopMac.interface = route->interface;

				send_packet(&arpRequest_nextHopMac);
			}
		}
	}
}
