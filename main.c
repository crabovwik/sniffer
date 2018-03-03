#include <stdio.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <libnet.h>
#include "helper.h"
#include "network.h"

void pcap_fatal(const char *, const char *);

void decode_ethernet(const u_char *);

void decode_ip(const u_char *);

u_int decode_tcp(const u_char *);

void caught_packet(u_char *, const struct pcap_pkthdr *, const u_char *);

int main() {
    struct pcap_pkthdr cap_header;
    const u_char *packet, *pkt_data;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *device;

    pcap_t *pcap_handle;

    device = pcap_lookupdev(errbuf);
    if (device == NULL)
        pcap_fatal("pcap_lookupdev", errbuf);

    printf("Sniffing on device %s\n", device);

    pcap_handle = pcap_open_live(device, 4096, 1, 0, errbuf);
    if (pcap_handle == NULL)
        pcap_fatal("pcap_open_live", errbuf);

    pcap_loop(pcap_handle, 3, caught_packet, NULL);

    pcap_close(pcap_handle);
}

void caught_packet(u_char *user_args, const struct pcap_pkthdr *cap_header, const u_char *packet) {
    unsigned int tcp_header_length, total_header_size, pkt_data_len;
    char *pkt_data;

    printf("==== Got a %d byte packet ====\n", cap_header->len);

    decode_ethernet(packet);
    decode_ip(packet + NETWORK_ETHER_HEADER_LEN);
    tcp_header_length = decode_tcp(packet + NETWORK_ETHER_HEADER_LEN + sizeof(struct network_ip_header));

    total_header_size = NETWORK_ETHER_HEADER_LEN + sizeof(struct network_ip_header) + tcp_header_length;
    pkt_data = (char *) packet + total_header_size;
    pkt_data_len = cap_header->len - total_header_size;
    if (pkt_data_len > 0) {
        printf("\t\t\t%u bytes of packet data\n", pkt_data_len);
        dump(pkt_data, pkt_data_len);
    } else
        printf("\t\t\tNo Packet Data\n");
}

void pcap_fatal(const char *failed_in, const char *errbuf) {
    printf("Fatal Error in %s: %s\n", failed_in, errbuf);
    exit(1);
}

void decode_ethernet(const u_char *header_start) {
    int i;
    const struct network_ether_header *ethernet_header;

    ethernet_header = (const struct network_ether_header *) header_start;

    printf("[[  Layer 2 :: Ethernet Header  ]]\n");
    printf("[ Source: %02x", ethernet_header->ether_src_address[0]);

    for (i = 1; i < ETHER_ADDR_LEN; i++) {
        printf(":%02x", ethernet_header->ether_src_address[i]);
    }

    printf("\tDest: %02x", ethernet_header->ether_dest_address[0]);
    for (i = 1; i < ETHER_ADDR_LEN; i++) {
        printf(":%02x", ethernet_header->ether_dest_address[i]);
    }

    printf("\tType: %hu ]\n", ethernet_header->ether_type);
}

void decode_ip(const u_char *header_start) {
    const struct network_ip_header *ip_header;

    ip_header = (const struct network_ip_header *) header_start;
    printf("\t((  Layer 3 ::: IP Header  ))\n");
    printf("\t( Source: %s\t", inet_ntoa(*(struct in_addr *) &ip_header->ip_source_address));
    printf("Dest: %s )\n", inet_ntoa(*(struct in_addr *) &ip_header->ip_destination_address));
    printf("\t( Type: %u\t", (u_int) ip_header->tos);
    printf("ID: %hu\tLength: %hu )\n", ntohs(ip_header->identification), ntohs(ip_header->length));
}

u_int decode_tcp(const u_char *header_start) {
    u_int header_size;
    const struct network_tcp_header *tcp_header;

    tcp_header = (const struct network_tcp_header *) header_start;
    header_size = 4 * (unsigned int) tcp_header->data_offset;

    printf("\t\t{{  Layer 4 :::: TCP Header  }}\n");
    printf("\t\t{ Src Port: %hu\t", ntohs(tcp_header->source_port));
    printf("Dest Port: %hu }\n", ntohs(tcp_header->destination_port));
    printf("\t\t{ Seq #: %u\t", ntohl(tcp_header->sequence_number));
    printf("Ack #: %u }\n", ntohl(tcp_header->acknowledgment_number));
    printf("\t\t{ Header Size: %u\tFlags: ", header_size);
    if (tcp_header->flags & NETWORK_TH_FIN)
        printf("FIN ");
    if (tcp_header->flags & NETWORK_TH_SYN)
        printf("SYN ");
    if (tcp_header->flags & NETWORK_TH_RST)
        printf("RST ");
    if (tcp_header->flags & NETWORK_TH_PUSH)
        printf("PUSH ");
    if (tcp_header->flags & NETWORK_TH_ACK)
        printf("ACK ");
    if (tcp_header->flags & NETWORK_TH_URG)
        printf("URG ");
    printf(" }\n");

    return header_size;
}
