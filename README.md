Blotiu Mihnea-Andrei - 323CA
Protocoale de comunicatie - Tema 1 - Router Data Plane


The overall point of this project is to implement a router data plane, which
actually means the implementation of the forwarding process

This was done accordingly to the indications we had and that being said, the
project was structured as follows:

    - router.c the main file of this project where everything happens;
    - skel.c/skel.h the functions and the headers of the functions offered
    as base;
    - queue.c/queue.h the functions and the headers of the implementation
    of a queue used to store the packages that were waiting for an ARP
    Reply;
    - list.c/list.h the functions and the headers of the implementation
    of a list needed by the queue;
    - arp_ip_icmp.c/arp_ip_icmp.h the functions and the headers of the
    helper functions used in router.c to manipulate ARP, IP and ICPM
    packets as well as the routing tabel.

In this project I implemented the folowing aspects:

    - ARP Protocol such that the router can work without a static ARP table (30p);
    - Forwarding process (IPv4) (30p);
    - ICMP Protocol such that the router can send back messages in case of
    error or if he gets an echo request (20p);
    - Partially implemented the LPM efficient with a binary search (15p);
    - BONUS: the update of the checksum using RFC 1624(10p);
    - README: 5p;

    TOTAL: 110p;

The hole flow of the project is described by the router.c file as follows:

*router.c:
    - First of all we initialise all the structures that we are going to use:
    the routing table, the length of the routing table, the queue used for the
    waiting packets and the ARP Cache table;
    - We also sort the routing table based on the prefix and in case of equality
    based on the mask because we know that we are going to do binary searches
    when we need a route;
    - In a while true loop, we are waiting for packets to come;
    - When a packet comes, we first check if it contains at least the Layer two
    header, the Ethernet header;
    - If it does, we have to make sure that the packet is for the router or not
    (the MAC destination address of the packet is the same with the MAC address
    of the interface on which the router got the packet / the packet is broadcasted);
    - If the packet got correctly to the router we have to find out what type of 
    packet it is:

    *ARP Packets:
    - If the packet is an ARP one, we have to check whether it is an ARP Request;
    or an ARP Reply. First of all, let's talk about ARP Requests.

    *ARP Request:
    - If the packet is an ARP Request, it means that a host is trying to find out
    our MAC address. That being said, we have to prepare the packet and send
    it back;
    - We just swap the destination IP and MAC addresses with the source mac
    addresses and send the packet back to where it came from.

    *ARP Reply:
    - If the packet is an ARP Reply, it means it is a Reply from a previous
    request we made because we needed a MAC address of the next hop where we
    should deliver a packet;
    - That being said, we now create a new entry in the ARP Cache with the
    senders IP and MAC address (the one that responded to our ARP Request);
    - If the ARP Cache doesn't contain the ip address from which we just received
    the reply, we add it;
    - We also iterate through the queue of packets that were waiting for an MAC
    and if we find one that now has the MAC, we send it, otherwise we just
    keep them in the queue for the following ARP Replies.

    *IP Packets:
    - If the packet is an IP one we have to check whether the IP packet has the
    router as the final destination or we have just to forward it;
    - If the packet has the router as the final destination, we have to answer
    only if it is an echo request with an echo reply;
    - If the packet is an echo request we just send the packet back to where it
    came from as an echo reply (type 0, code 0);
    - If the packet has not got the router as the final destination, we try
    to forward it to the next hop;
    - First of all we check if the checksum and the TTL is correct. If not, we
    send and ICMP to the source of the packet and drop the packet;
    - If they are correct we search in the routing table for the best route
    for this packet. If there is no route for this packet, we send an ICMP
    error back to the source and we drop the packet;
    - If we also find the route, we update the ttl and the checksum using
    RFC 1624 because we just changed the ttl so no need to recalculate everything;
    - Now, we have to check if we have the next hop's MAC of the route in our
    ARP Cache table. If we have it, we just send it on the correct interface
    with the correct MAC;
    - If we don't have the MAC in our cache, we prepare the packet and add
    it in the queue just waiting for the MAC address.
    - In order to obtain the MAC address, we create a new ARP request for 
    everybody(broadcast) and we send it on the next hop interface (because we 
    know that there is going to be the next hop from which we need the MAC).
    - We send the packet and wait for a reply.

*arp_ip_icmp.c:
    * compareFunction:
        - The compare function used by quicksort in order to sort the routing
        table by prefix and in case of equality by mask;

    * get_best_routeBinarySearch:
        - The binary search function that gets the best route in the sorted
        routing table (it is just a recursive binary search that checks if the
        prefix of the middle entry matches the IP address and then goes to the
        biggest mask -> as much to the left as possible because the routing table
        was sorted in descending order);
        - However, even though it respects the algorithm described in the paper
        where we got the task, it fails sometimes (3 tests out of all) so I did
        not use it in the code as I wanted all the tests to pass;
        - However I let it in the functions file because I think it is partially
        corret and I can have some points out of the 15p given for the
        LPM efficient.

    *get_best_route:
        - The LPM linear search that works with no problem on all the tests
        (inspired from LAB 4 - Forwarding);

    *arpCacheContainsEntry:
        - Returns the coresponding MAC of an IP address if it exists in the
        ARP Cache.

    *checkIfMacIsForRouter:
        - Checks whether a packet that arrived to the router should have been
        there or not;

    *constructIcmpPacket:
        - The function that constructs and ICMP packet from scrach with a specific;
        code, type and 64 bytes from the original packet;
        - This packet is going to be sent in case of error when searching a route
        or when the TTL is not high enough. (inspired from the original
        functions in the original skel that was afterwards deleted from moodle)

    *nextHopMatches:
        - The function that checks if a packet has the next hop's MAC in the
        ARP Cache and if affirmative, it sets it as a destination for the packet;

    *updateIpChecksum:
        - The function that updates the checksum when we change just the TTL
        according to the RFC 1624 formula.

*skel.c/skel.h/queue.c/queue.h/list.c/list.h:
    - Are the exat same files that were given in the skel in the archive.

*Makefile


Dificulties durring the project:

1.It is pretty hard to understand how the checker is working as we were usually
used to check just by one command;

2.The paper with the task is pretty vague. It is very hard to understand the
tasks even if now, after I finished the homework, it is pretty clear what I had
to do. But when you first read it, is hard;

3.The RFC 1624 formula did not return exacty what I expected, I observed that
it was always one bigger than the actual correct checksum so I had to adapt it;

4.The binary search was by far the hardest task in this project. Even if the
final result is decent, I followed exactly the instructions given and the
algorithm is not perfect;

References:

1.Binary search: https://www.geeksforgeeks.org/binary-search/;
2.Forwarding lab (lab 4) for the IP forwarding part and for finding the best route;
3.The initial ICMP functions from the skel when constructing the packets
(i wrote exactly where I was used those functions);
4.RFC 1624 Checksum - https://datatracker.ietf.org/doc/html/rfc1624.

