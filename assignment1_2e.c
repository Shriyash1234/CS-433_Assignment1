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

    // Check if the source IP is "127.0.0.1" (localhost)
    if (strcmp(source_ip, "127.0.0.1") == 0) {
        // Extract the TCP header, skipping the IP header (variable length)
        tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl << 2)); // Skip IP header

        // Extract HTTP data by skipping Ethernet, IP, and TCP headers
        const char *http_data = (const char *)(packet + 14 + (ip_header->ip_hl << 2) + (tcp_header->th_off << 2));
        const char *content_type = strstr(http_data, "Content-Type: ");
            
        if (content_type != NULL) {
            // Advance the content_type pointer past "Content-Type: " and find the end of the line
            content_type += strlen("Content-Type: ");
            const char *line_end = strchr(content_type, '\r');
            if (line_end != NULL) {
                // Print the Content-Type value
                printf("Content-Type: %.*s\n", (int)(line_end - content_type), content_type);
            }
        }
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
