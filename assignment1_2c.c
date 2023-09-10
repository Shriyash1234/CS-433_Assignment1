#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define TCP_CHECKSUM 0x46a4

void process_packet(const struct pcap_pkthdr *header, const u_char *packet) {
    // Extract the IP header from the packet (assuming Ethernet frames)
    struct ip *ip_header = (struct ip*)(packet + 14);

    // Check if the packet contains TCP data
    if (ip_header->ip_p == IPPROTO_TCP) {
        // Extract the TCP header from the packet
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + ip_header->ip_hl * 4);

        // Check if TCP checksum matches the desired value
        if (ntohs(tcp_header->th_sum) == TCP_CHECKSUM) {
            printf("TCP Checksum Match: %04x\n", TCP_CHECKSUM);

            // Assuming HTTP traffic starts with "GET" or "POST" methods
            if (strstr((char *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4), "GET") ||
                strstr((char *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4), "POST")) {
                // Print the HTTP request
                printf("HTTP Request:\n%s\n", (char *)(packet + 14 + ip_header->ip_hl * 4 + tcp_header->th_off * 4));
            }
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    // Get the filename of the pcap file from command-line arguments
    char *pcap_file = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];

    // Open the pcap file for reading
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);

    if (handle == NULL) {
        printf("Error opening pcap file: %s\n", errbuf);
        return 1;
    }

    struct pcap_pkthdr header;
    const u_char *packet;

    // Loop through each packet in the pcap file
    while ((packet = pcap_next(handle, &header)) != NULL) {
        // Process the packet
        process_packet(&header, packet);
    }

    // Close the pcap file
    pcap_close(handle);
    return 0;
}
