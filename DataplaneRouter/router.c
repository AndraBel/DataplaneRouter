#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <net/if_arp.h>

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define RTABLE_MAX_SIZE 100000
#define INIT_ARP_SIZE 10
#define MAC_SIZE 6


// ICMP
#define ICMP_ECHOREPLY		0	/* Echo Reply */
#define ICMP_DEST_UNREACH	3	/* Destination Unreachable */
#define ICMP_ECHO		8		/* Echo Request	*/
#define ICMP_TIME_EXCEEDED	11	/* Time Exceeded */


struct route_table_entry *rtable;
int size_rtable;

struct arp_table_entry *arp_table;
int arp_table_size;
int arp_table_length;

queue packege_queue;

/* functie de comparare pentru qsort care sorteaza intrarile in functie de
   prefix & masca, iar in caz de egalitate iau pe cel cu masca mai mare */
int compare_function(const void *a, const void *b){
	struct route_table_entry *x = (struct route_table_entry*)a;
	struct route_table_entry *y = (struct route_table_entry*)b;
	
	if (ntohl(x->prefix & x->mask) < ntohl(y->prefix & y->mask)) {
		return -1;
	}
	if (ntohl(x->prefix & x->mask) > ntohl(y->prefix & y->mask)) {
		return 1;
	}
	if (ntohl(x->mask) < ntohl(y->mask)) {
		return -1;
	}
	if (ntohl(x->mask) > ntohl(y->mask)) {
		return 1;
	}
	return 0;
}

// functie care returneaza route table entry-ul care contine LPM ul
struct route_table_entry *get_best_route(uint32_t dest_ip, int rtable_size) {
	struct route_table_entry *bestMatch = NULL;
	int left = 0, right = rtable_size - 1;

	while (left <= right) {
		int mid = (left + right) / 2;

		/* chiar daca s-a gasit un best_route se continua cautarea
		in caz ca gasim o intrare cu masca mai mare */
		if (ntohl(dest_ip & rtable[mid].mask) ==
							ntohl(rtable[mid].prefix & rtable[mid].mask) ) {
			bestMatch = &rtable[mid];
			left = mid + 1;
		} else if (ntohl(rtable[mid].prefix & rtable[mid].mask) <
							ntohl(dest_ip & rtable[mid].mask)) {
			left = mid + 1;
		} else {
			right = mid - 1;
		}
	}
	return bestMatch;
}

// citesc route tabelul, il realoc daca este necesar, apoi il sortez
int init_rtable(char *path, struct route_table_entry *rtable) {
	
	int size_rtable_new = read_rtable(path, rtable);

	if (size_rtable_new < RTABLE_MAX_SIZE) {
		rtable = realloc(rtable, sizeof(struct route_table_entry) *
						 size_rtable_new);
		DIE(rtable == NULL, "reallocation rtable failed");
	}	  

	qsort(rtable, 
    	  size_rtable_new, 
    	  sizeof(struct route_table_entry), 
    	  compare_function);

	return size_rtable_new;		  
}

void init_arp_tabel() {
	arp_table = (struct arp_table_entry *)malloc(sizeof(struct arp_table_entry) *
												 INIT_ARP_SIZE);
	DIE(arp_table == NULL, "allocation failed for ARP");

	arp_table_size = INIT_ARP_SIZE;
	arp_table_length = 0;
}

void add_arp_table_entry(uint32_t ip, uint8_t *mac){
	// realoc tabela arp daca este cazul
	if (arp_table_length == arp_table_size - 1) {
		arp_table = (struct arp_table_entry *)realloc(arp_table, 
									   sizeof(struct arp_table_entry) * 2 *
									   arp_table_size);
		arp_table_size = 2 * arp_table_size;
	}

	// Adaug o noua intrare in ARP
	arp_table[arp_table_length].ip = ip;
	memcpy(arp_table[arp_table_length].mac, mac, 6);

	arp_table_length++;
}

struct arp_table_entry* find_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_length; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

void send_arp(uint32_t sender_ip, uint8_t *sender_mac, 
			  uint32_t target_ip, uint8_t *target_mac,
			  int interface, char *old_package,
			  uint16_t op_type) {
	// fac un pachet nou
	char package[MAX_PACKET_LEN];
	memcpy(package, old_package, MAX_PACKET_LEN);

	// construiesc antetul de ethernet
	struct ether_header *eth_hdr = (struct ether_header *)package;
	eth_hdr->ether_type = ntohs(ETHERTYPE_ARP);

	memcpy(eth_hdr->ether_dhost, target_mac, MAC_SIZE * sizeof(uint8_t));
	memcpy(eth_hdr->ether_shost, sender_mac, MAC_SIZE * sizeof(uint8_t));

	// construiesc antetul de arp
	struct arp_header *arp_hdr = (struct arp_header *)(package +
								  sizeof(struct ether_header));
	arp_hdr->htype = htons(ARPHRD_ETHER);
	arp_hdr->ptype = htons(2048);
	arp_hdr->hlen = 6;
	arp_hdr->plen = 4;
	
	arp_hdr->op = op_type;
	memcpy(arp_hdr->sha, sender_mac, MAC_SIZE * sizeof(uint8_t));
	memcpy(arp_hdr->tha, target_mac, MAC_SIZE * sizeof(uint8_t));

	arp_hdr->spa = sender_ip;
	arp_hdr->tpa = target_ip;

	// trimit pachetul
	int ret = send_to_link(interface, package, sizeof(struct arp_header) +
						   sizeof(struct ether_header));
	DIE(ret == -1, "failed to send package");

}

void handle_arp(struct arp_header *arp_hdr, int interface,
				struct ether_header *eth_hdr, char *package) {
	struct in_addr interface_ip;
	uint8_t interface_mac[6];

	/* in intrface_ip iau ip-ul interfetei cu functia ajutatoare
	si cu o conversie inet_aton */
	int ret = inet_aton(get_interface_ip(interface), &interface_ip);
	if (ret == 0) {
		return;
	}

	get_interface_mac(interface, interface_mac);

	// daca am arp request
	if (arp_hdr->op == htons(ARPOP_REQUEST)) {
		/* adresa ip e a interfetei routerului, trimit arp replay
		cu adresa mac a interfetei routerului */
		if (interface_ip.s_addr == arp_hdr->tpa) {
			send_arp(interface_ip.s_addr, interface_mac, arp_hdr->spa,
					 arp_hdr->sha, interface, package, htons(ARPOP_REPLY));
		} 
	} else if (arp_hdr->op == htons(ARPOP_REPLY)) {
		/* daca nu gasesc sender ul in tabela de arp, il adaug */
		if (find_arp_entry(arp_hdr->spa) == NULL) {
			add_arp_table_entry(arp_hdr->spa, arp_hdr->sha);
		}

		while (!queue_empty(packege_queue)) {
			char *old_packet = (char *) queue_deq(packege_queue);

			struct ether_header *old_eth_hdr = (struct ether_header *)old_packet;
			struct iphdr *old_ip_hdr = (struct iphdr *)(old_packet +
													sizeof(struct ether_header));
			struct route_table_entry *best_route =
							get_best_route(old_ip_hdr->daddr, size_rtable);

			if (best_route) {
				struct arp_table_entry* found_arp =
								find_arp_entry(best_route->next_hop);
				/* daca gasesc un best route in tabela de rutare si
				ii stiu adresa mac a next hop ului trimit mai departe
				pachetul */
				if (found_arp) {
					old_ip_hdr->ttl--;

					// recalculez checksumul
					old_ip_hdr->check = 0;
					old_ip_hdr->check = htons(checksum((uint16_t *)old_ip_hdr,
											  sizeof(struct iphdr)));

					/* schimba adresa sursa mac cu adresa mac a interfetei
					pe care trebuie trimis pachetul */
					get_interface_mac(best_route->interface,
									  old_eth_hdr->ether_shost);

					// completez destinatia mac cu adresa mac a best route ului
					memcpy(old_eth_hdr->ether_dhost, found_arp->mac,
						   MAC_SIZE * sizeof(uint8_t));

					// trimit pachetul
					ret = send_to_link(best_route->interface, old_packet,
									   sizeof(struct ether_header) +
									   ntohs(old_ip_hdr->tot_len));
					DIE(ret == -1, "failed to send package");
				}
			}
			free(old_packet);
		}
	}
}

void send_icmp(uint32_t saddr, uint8_t *sha, uint32_t daddr, uint8_t *dha,
			   u_int8_t type, int interface, char* old_package){
	char package[MAX_PACKET_LEN];
	memcpy(package, old_package, MAX_PACKET_LEN);


	struct ether_header *eth_hdr = (struct ether_header *) package;
	struct iphdr *ip_hdr = (struct iphdr *)(package +
											sizeof(struct ether_header));
	struct icmphdr *icmp_hdr = (struct icmphdr *)(package +
												  sizeof(struct iphdr) +
												  sizeof(struct ether_header));

	// reconstruiesc antetul ethernet
	memcpy(eth_hdr->ether_dhost, dha, MAC_SIZE * sizeof(uint8_t));
	memcpy(eth_hdr->ether_shost, sha, MAC_SIZE* sizeof(uint8_t));

	// la fel cu antetul ip
	ip_hdr->daddr = daddr;
	ip_hdr->saddr = saddr;
	ip_hdr->protocol = IPPROTO_ICMP;
	ip_hdr->tot_len = htons(sizeof(struct icmphdr) + sizeof(struct iphdr));

	ip_hdr->ttl = 64;

	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	// in final si antetul pt icmp trebuie format
	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *)icmp_hdr,
							   sizeof(struct icmphdr)));

	int ret = send_to_link(interface, package, sizeof(struct iphdr) +
						   sizeof(struct ether_header) +
						   sizeof(struct icmphdr));
	DIE(ret == -1, "failed to send package");
}

void handle_ip(char *package, int interface, struct iphdr *ip_hdr) {
	struct in_addr interface_ip;
	
	int ret = inet_aton(get_interface_ip(interface), &interface_ip);
	if (ret == 0) {
		return;
	}

	uint8_t interface_mac[6];
	get_interface_mac(interface, interface_mac);

	struct ether_header *eth_hdr = (struct ether_header *) package;

	// se verifica daca routerul este destinatarul pachetului 
	if (interface_ip.s_addr == ip_hdr->daddr) {
		// daca e pachet de tip icmp
		if (ip_hdr->protocol == IPPROTO_ICMP) {
			struct icmphdr *icmp_hdr;
			icmp_hdr = (struct icmphdr *)(package +
						sizeof(struct iphdr) + sizeof(struct ether_header));

			// icmp echo trimite un echo reply 
			if (icmp_hdr->type == ICMP_ECHO) {
				send_icmp(interface_ip.s_addr, 
						  interface_mac, 
						  ip_hdr->saddr, 
						  eth_hdr->ether_shost, 
						  ICMP_ECHOREPLY, 
						  interface, 
						  package);
				return;
			}
		}
	}

	// verific checksum ul
	u_int16_t old_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;

	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != old_checksum) {
		return;
	}

	// verific ttl-ul si trimit eroarea specifica daca este necesar
	if (ip_hdr->ttl <= 1) {
		send_icmp(interface_ip.s_addr, 
				  interface_mac, 
				  ip_hdr->saddr, 
				  eth_hdr->ether_shost, 
				  ICMP_TIME_EXCEEDED, 
				  interface, 
				  package);
		return;		
	}

	// caut in tabela de rutare si in cazul in care nu gasesc
	//	trimit eroarea specifica
	struct route_table_entry *best_route =
							get_best_route(ip_hdr->daddr, size_rtable);

	if (best_route == NULL) {
		send_icmp(interface_ip.s_addr, 
				  		interface_mac, 
						ip_hdr->saddr, 
				  		eth_hdr->ether_shost, 
						ICMP_DEST_UNREACH, 
						interface, 
				  		package);
		return;		
	}

	// decrementez ttl-ul
	ip_hdr->ttl = ip_hdr->ttl - 1;
		
	// fac update la checksum
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	/* caut in tabela arp, iar in cazul in care nu se gaseste intrarea
	bag pachetul intr-o coada si trimit arp request */
	struct arp_table_entry* found_arp = find_arp_entry(best_route->next_hop);

	if (found_arp == NULL) {
		char *new_package = (char *)malloc(sizeof(char) * MAX_PACKET_LEN);
		DIE(new_package == NULL, "new package allocation failed");

		memcpy(new_package, package, sizeof(char) * MAX_PACKET_LEN);

		queue_enq(packege_queue, new_package);

		struct in_addr best_route_interface_ip;
		uint8_t best_route_interface_mac[6];
		get_interface_mac(best_route->interface, best_route_interface_mac);
		int ret = inet_aton(get_interface_ip(best_route->interface),
							&best_route_interface_ip);
		if (ret == 0) {
			return;
		}

		uint8_t broadcast_mac[6];
		hwaddr_aton("FF:FF:FF:FF:FF:FF", broadcast_mac);

		send_arp(best_route_interface_ip.s_addr, 
				best_route_interface_mac, 
				best_route->next_hop, 
				broadcast_mac, 
				best_route->interface, 
				package, 
				htons(ARPOP_REQUEST));

		return;
	}

	/* schimba adresa sursa mac cu adresa mac a interfetei
	pe care trebuie trimis pachetul */
	get_interface_mac(best_route->interface, eth_hdr->ether_shost);

	// completez destinatia mac cu adresa mac a best route ului
	memcpy(eth_hdr->ether_dhost, found_arp->mac, MAC_SIZE * sizeof(uint8_t));
	
	ret = send_to_link(best_route->interface, package,
					   sizeof(struct ether_header) + ntohs(ip_hdr->tot_len));
	DIE(ret == -1, "failed to send package");
}

void free_arp_table() {
	free(arp_table);
}

void free_rtable() {
	free(rtable);
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];
	struct arp_header *arp_hdr;
	struct iphdr *ip_hdr;

	// Do not modify this line
	init(argc - 2, argv + 2);

	rtable = malloc(sizeof(struct route_table_entry) * RTABLE_MAX_SIZE);
	DIE(rtable == NULL, "allocation rtable failed");

	// Aici tin size-ul route tabelului
	size_rtable = init_rtable(argv[1], rtable);
	init_arp_tabel();
	packege_queue = queue_create();

	while (1) {

		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		// iau tipul pachetului
		uint16_t eth_type = ntohs(eth_hdr->ether_type);

		switch (eth_type) {
			case ETHERTYPE_ARP:
				// daca pachetul este de tip ARP
				arp_hdr = (struct arp_header *)(buf +
											  sizeof(struct ether_header));
				handle_arp(arp_hdr, interface, eth_hdr, buf);
				break;
			case ETHERTYPE_IP:
				// iau antetul ip care se afla dupa antetul ethernet
				ip_hdr = (struct iphdr *)(buf +
										sizeof(struct ether_header));
				handle_ip(buf, interface, ip_hdr);
				break;
			default:
				break;
		}
	}

	free_rtable();
	free_arp_table();
}

