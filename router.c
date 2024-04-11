#include "queue.h"
#include "lib.h"
#include "protocols.h"
#include <arpa/inet.h>
#include <string.h>
#include <linux/if_ether.h>

#define p_ethhdr struct ether_header *
#define p_iphdr struct iphdr *
#define p_arphdr struct arp_header *
#define p_icmphdr struct icmphdr *

const uint8_t ip_hdr_start = sizeof(struct ether_header);
const uint8_t ip_data = ip_hdr_start + sizeof(struct iphdr);

const uint8_t arp_hdr_start = sizeof(struct ether_header);
const uint8_t arp_data = arp_hdr_start + sizeof(struct arp_header);
const uint16_t arp_len = sizeof(struct ether_header) + sizeof(struct arp_header);

const uint8_t icmp_hdr_start = ip_hdr_start + sizeof(struct iphdr);
const uint8_t icmp_data = icmp_hdr_start + sizeof(struct icmphdr);
const uint16_t icmp_len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr) + 8;

const uint8_t broadcast[ETH_ALEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
const uint16_t opRequest = 1;
const uint16_t opReply = 2;

const uint8_t icmpTE = 11;
const uint8_t icmpDU = 3;
const uint8_t icmpRequest = 8;
const uint8_t icmpReply = 0;

const uint8_t protocolReserved = 0;
const uint8_t protocolICMP = 1;

struct route_table_entry *rtable;
int rtable_len;

struct arp_table_entry *arp_table;
int arp_table_len;

queue coada;
int arp_queue_len;

struct node
{
    struct route_table_entry *rtable_entry;
    struct node *bit[2];
} *root;

struct info
{
	char buf[MAX_PACKET_LEN];
	size_t len;
	struct route_table_entry *rtable_entry;
};

struct node* createNode() {
    struct node* newNode = (struct node*)malloc(sizeof(struct node));

	newNode->bit[0] = newNode->bit[1] = NULL;
    newNode->rtable_entry = NULL;
    return newNode;
}

void insert(struct node* root, uint32_t value, int bits_mask, struct route_table_entry* rtable_entry) {
    struct node* currentNode = root;

	for (int j=31; j>=0; j--) {
		int bit = ((value & (1<<j))>>j);

		if (currentNode->bit[bit] == NULL)
			currentNode->bit[bit] = createNode();
		currentNode = currentNode->bit[bit];
		if (j + bits_mask == 32) currentNode->rtable_entry = rtable_entry;
	}
}

struct route_table_entry* find_prefix(struct node* root, uint32_t value) {
	struct node* currentNode = root;
	struct route_table_entry* route_entry = NULL;

	for (int j=31; j>=0; j--) {
		int bit = ((value & (1<<j))>>j);

		if (currentNode->bit[bit] == NULL)
			return route_entry;
		currentNode = currentNode->bit[bit];
		if (currentNode->rtable_entry != NULL) route_entry = currentNode->rtable_entry;
	}
	return route_entry;
}

struct route_table_entry *get_best_route(uint32_t ip_dest) {
	return find_prefix(root, ntohl(ip_dest));
}

char* create_Arp(uint16_t op, uint32_t spa, uint8_t sha[ETH_ALEN], uint32_t tpa, uint8_t tha[ETH_ALEN])
{
	char* packet = (char*) malloc(arp_len);
	p_ethhdr eth_hdr = (p_ethhdr) packet;
	p_arphdr arp_hdr = (p_arphdr)(packet + arp_hdr_start);

	eth_hdr->ether_type = htons(ETH_P_ARP);
	arp_hdr->htype = htons(1);
	arp_hdr->ptype = htons(ETH_P_IP);
	arp_hdr->hlen = ETH_ALEN;
	arp_hdr->plen = 4;
	arp_hdr->op = htons(op);
	arp_hdr->spa = spa;
	memcpy(eth_hdr->ether_shost, sha, ETH_ALEN);
	memcpy(arp_hdr->sha, sha, ETH_ALEN);
	arp_hdr->tpa = tpa;
	memcpy(eth_hdr->ether_dhost, tha, ETH_ALEN);
	memcpy(arp_hdr->tha, tha, ETH_ALEN);

	return packet;
}

void send_ICMP(char *packet, size_t len, int interface, uint8_t type)
{
	p_ethhdr eth_hdr = (p_ethhdr) packet;
	p_iphdr ip_hdr = (p_iphdr) (packet + ip_hdr_start);
	p_icmphdr icmp_hdr = (p_icmphdr) (packet + icmp_hdr_start);

	if (ip_hdr->protocol == protocolICMP) {
		if (icmp_hdr->type == icmpRequest) {
			if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
				printf("Pachet corupt\n");
				return;
			}
			if (checksum((uint16_t *)icmp_hdr, sizeof(struct icmphdr)) != 0) {
				printf("Pachet corupt\n");
				return;
			}
		} else return;
	} else if (ip_hdr->protocol == protocolReserved) {
		len = icmp_len;
		char *data = packet + icmp_data;
		memmove(data, icmp_hdr, 8);
		ip_hdr->tot_len = htons(icmp_len - sizeof(struct ether_header));
	} else return;

	icmp_hdr->type = type;
	icmp_hdr->code = 0;
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = htons(checksum((uint16_t *) icmp_hdr, sizeof(struct icmphdr)));

	struct route_table_entry *best_route = get_best_route(ip_hdr->saddr);
	if (best_route == NULL) {
		printf("Pachet corupt\n");
		return;
	}

	ip_hdr->ttl = 64;
	ip_hdr->protocol = protocolICMP;
	ip_hdr->daddr = ip_hdr->saddr;
	ip_hdr->saddr = inet_addr(get_interface_ip(best_route->interface));
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));

	for (int i=0; i<ETH_ALEN; i++) {
		uint8_t aux = eth_hdr->ether_dhost[i];
		eth_hdr->ether_dhost[i] = eth_hdr->ether_shost[i];
		eth_hdr->ether_shost[i] = aux;
	}

	send_to_link(best_route->interface, packet, len);
}

int check_Cache(char* packet, size_t len, struct route_table_entry* best_route)
{
	p_ethhdr eth_hdr = (p_ethhdr) packet;

	for (int i = 0; i < arp_table_len; i++)
		if (ntohl(arp_table[i].ip) == ntohl(best_route->next_hop)) {
			memcpy(eth_hdr->ether_dhost, arp_table[i].mac, ETH_ALEN);
			send_to_link(best_route->interface, packet, len);
			return 1;
		}
	
	return 0;
}

void add_in_Queue(char* packet, size_t len, struct route_table_entry* best_route)
{
	struct info* Info = (struct info*) malloc(sizeof(struct info));
	memcpy(Info->buf, packet, len);
	Info->len = len;
	Info->rtable_entry = best_route;
	queue_enq(coada, (void *) Info);
	arp_queue_len++;
}

void IP_type(char *buf, size_t len, int interface)
{
	p_iphdr ip_hdr = (p_iphdr) (buf + ip_hdr_start);

	if (checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)) != 0) {
		printf("Pachet corupt\n");
		return;
	}

	struct route_table_entry *best_route = get_best_route(ip_hdr->daddr);

	if (best_route == NULL) {
		send_ICMP(buf, len, interface, icmpDU);
		return;
	}

	if (ip_hdr->ttl < 2) {
		send_ICMP(buf, len, interface, icmpTE);
		return;
	}

	ip_hdr->ttl -= 1;
	ip_hdr->check = 0;
	ip_hdr->check = htons(checksum((uint16_t *)ip_hdr, sizeof(struct iphdr)));
	
	if (check_Cache(buf, len, best_route)) return;

	add_in_Queue(buf, len, best_route);

	char *packet = NULL;
	uint8_t sha[ETH_ALEN], tha[ETH_ALEN];
	get_interface_mac(best_route->interface, sha);
	memcpy(tha, broadcast, ETH_ALEN);

	packet = create_Arp(opRequest, inet_addr(get_interface_ip(best_route->interface)), sha, best_route->next_hop, tha);

	send_to_link(best_route->interface, packet, arp_len);
}

void ARP_type(char *buf, size_t len, int interface)
{
	p_arphdr arp_hdr = (p_arphdr)(buf + ip_hdr_start);

	char *packet = NULL;

	if (arp_hdr->op == htons(opRequest)) {
		struct route_table_entry *best_route = get_best_route(arp_hdr->spa);

		uint8_t sha[ETH_ALEN], tha[ETH_ALEN];
		memcpy(tha, arp_hdr->sha, ETH_ALEN);
		get_interface_mac(best_route->interface, sha);

		packet = create_Arp(opReply, arp_hdr->tpa, sha, arp_hdr->spa, tha);

		send_to_link(best_route->interface, packet, arp_len);
		return;
	}
	if (arp_hdr->op == htons(opReply)) {
		arp_table[arp_table_len].ip = arp_hdr->spa;
		memcpy(arp_table[arp_table_len].mac, arp_hdr->sha, ETH_ALEN);
		arp_table_len++;

		int packets_removed = 0;

		for (int i = 0; i < arp_queue_len; i++) {
			struct info* Info = queue_deq(coada);

			if (ntohl(Info->rtable_entry->next_hop) == ntohl(arp_hdr->spa)) {
				memcpy(((p_ethhdr) Info->buf)->ether_dhost, arp_hdr->sha, ETH_ALEN);
				get_interface_mac(Info->rtable_entry->interface, ((p_ethhdr) Info->buf)->ether_shost);

				send_to_link(Info->rtable_entry->interface, Info->buf, Info->len);
				packets_removed++;
			} else
				queue_enq(coada, Info);
		}
		arp_queue_len -= packets_removed;

		return;
	}
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

    // Do not modify this line
    init(argc - 2, argv + 2);

    // Allocate ARP and route tables
    rtable = malloc(sizeof(struct route_table_entry) * 100000);
    DIE(rtable == NULL, "Malloc failed at rtable");
	rtable_len = read_rtable(argv[1], rtable);

    arp_table = malloc(sizeof(struct arp_table_entry) * 100000);
    DIE(arp_table == NULL, "Malloc failed at mac_table");
	arp_table_len = 0;

	coada = queue_create();
	arp_queue_len = 0;

	root = createNode();

	for (int i=0; i<rtable_len; i++) {
		insert(root, ntohl(rtable[i].prefix), __builtin_popcount(rtable[i].mask), &rtable[i]);
	}
	
	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		p_ethhdr eth_hdr = (p_ethhdr) buf;
		p_iphdr ip_hdr = (p_iphdr) (buf + ip_hdr_start);

		if (eth_hdr->ether_type == ntohs(ETH_P_IP)) {
			if (ip_hdr->daddr == inet_addr(get_interface_ip(interface)))
				send_ICMP(buf, len, interface, icmpReply);
			else IP_type(buf, len, interface);
		}
		else if (eth_hdr->ether_type == ntohs(ETH_P_ARP)) {
			ARP_type(buf, len, interface);
		}
	}
}