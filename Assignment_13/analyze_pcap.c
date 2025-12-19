#include <stdio.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/ip_icmp.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_offline(argv[1], errbuf);
    if (!pcap) {
        printf("Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr *header;
    const unsigned char *data;
    int count = 0;

    printf("=== TIME DIAGRAM ===\n");
    printf("Pkt#    Time(sec)       Protocol\n");

    int has_eth = 0, has_ip = 0, has_icmp = 0;

    while (pcap_next_ex(pcap, &header, &data) == 1) {
        count++;

        double ts = header->ts.tv_sec + header->ts.tv_usec / 1000000.0;

        // L2 header
        struct ether_header *eth = (struct ether_header *)data;
        has_eth = 1;

        if (ntohs(eth->ether_type) == ETHERTYPE_IP) {
            has_ip = 1;

            struct ip *iph = (struct ip *)(data + sizeof(struct ether_header));

            if (iph->ip_p == IPPROTO_ICMP) {
                has_icmp = 1;
                printf("%d\t%f\tICMP\n", count, ts);
            }
        }
    }

    printf("\n=== UNIQUE PROTOCOLS FOUND ===\n");
    if (has_eth) printf("L2: Ethernet\n");
    if (has_ip) printf("L3: IPv4\n");
    if (has_icmp) printf("L4: ICMP\n");

    pcap_close(pcap);
    return 0;
}

