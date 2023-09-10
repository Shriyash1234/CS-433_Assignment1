#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

// Function to handle packets
void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    struct ip *ip_header;
    struct tcphdr *tcp_header;

    // Extract the IP header from the packet, skipping the Ethernet header (14 bytes)
    ip_header = (struct ip*)(packet + 14);

    char source_ip[INET_ADDRSTRLEN];
    char dest_ip[INET_ADDRSTRLEN];

    // Convert source and destination IP addresses from binary to string format
    inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

    // Check if either the source or destination IP is "131.144.126.118"
    if (strcmp(source_ip, "131.144.126.118") == 0 || strcmp(dest_ip, "131.144.126.118") == 0) {
        // If IP matches, extract TCP header, skipping the IP header (variable length)
        tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

        // Extract source and destination ports and convert them from network byte order to host byte order
        unsigned short source_port = ntohs(tcp_header->th_sport);
        unsigned short dest_port = ntohs(tcp_header->th_dport);

        // Print source and destination ports
        printf("Source Port: %d\n", source_port);
        printf("Destination Port: %d\n", dest_port);

        // Calculate the sum of connection ports (accumulative)
        static unsigned long long port_sum = 0;
        port_sum += source_port + dest_port;
        printf("Sum of Connection Ports: %llu\n", port_sum);
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open a pcap file for offline packet capture
    handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    // Start packet capture loop, calling packet_handler for each captured packet
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        fprintf(stderr, "Error in pcap loop\n");
        return 1;
    }

    // Close the pcap file
    pcap_close(handle);
    return 0;
}
