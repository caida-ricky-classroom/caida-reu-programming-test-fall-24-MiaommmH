#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h> // Added to use inet_ntoa function

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    // Open the pcap file for reading
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Check if the packet is large enough to contain an Ethernet header
        if (header.caplen < sizeof(struct ethhdr)) {
            fprintf(stderr, "Packet %d is too small to contain an Ethernet header.\n", ++packet_count);
            continue;
        }

        // Move the pointer to the start of the IP header
        ip_header = (struct iphdr *)(packet + sizeof(struct ethhdr));

        // Check if the packet is large enough to contain an IP header
        if (header.caplen < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
            fprintf(stderr, "Packet %d is too small to contain an IP header.\n", ++packet_count);
            continue;
        }

        // Convert the destination IP address to a readable format
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_header->daddr;
        printf("Packet %d: IP destination address: %s\n", ++packet_count, inet_ntoa(ip_addr));
    }

    // Close the pcap file
    pcap_close(handle);
    return 0;
}
