#include <pcap.h>
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>    // For inet_ntoa function
#include <string.h>       // For memset

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    const unsigned char *packet;
    struct pcap_pkthdr header;
    struct iphdr *ip_header;
    int packet_count = 0;
    int last_octet_count[256]; // Array to store counts of each last octet value

    // Initialize the count array to zero
    memset(last_octet_count, 0, sizeof(last_octet_count));

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap file>\n", argv[0]);
        return 1;
    }

    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Check if the packet is large enough to contain an Ethernet and IP header
        if (header.caplen < sizeof(struct ether_header) + sizeof(struct iphdr)) {
            fprintf(stderr, "Packet %d is too small to contain Ethernet and IP headers.\n", ++packet_count);
            continue;
        }

        // Move the pointer to the start of the IP header
        ip_header = (struct iphdr *)(packet + sizeof(struct ether_header));

        // Extract the destination IP address
        struct in_addr ip_addr;
        ip_addr.s_addr = ip_header->daddr;

        // Convert the destination IP address to a readable string
        char *ip_str = inet_ntoa(ip_addr);

        // Extract the last octet value
        int last_octet;
        sscanf(strrchr(ip_str, '.') + 1, "%d", &last_octet); // Extract the last octet using sscanf

        // Increment the count for this last octet value
        if (last_octet >= 0 && last_octet <= 255) {
            last_octet_count[last_octet]++;
        }

        // Increment the packet count
        packet_count++;
    }

    pcap_close(handle);

    // Print the counts for each last octet value
    for (int i = 0; i < 256; i++) {
        if (last_octet_count[i] > 0) {
            printf("Last octet %d: %d\n", i, last_octet_count[i]);
        }
    }

    return 0;
}
