#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>

int main() {
    // Create a raw socket to capture TCP packets.
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(struct sockaddr_in));

    // Set up socket address structure.
    sa.sin_family = AF_INET;
    sa.sin_port = htons(0);  // Listen on any port.
    sa.sin_addr.s_addr = htonl(INADDR_ANY);  // Listen on any network interface.

    // Bind the socket to the network interface.
    if (bind(sockfd, (struct sockaddr*)&sa, sizeof(struct sockaddr_in)) < 0) {
        perror("Binding failed");
        close(sockfd);
        exit(1);
    }

    while (1) {
        char buffer[65536];  // Buffer to store received packets.

        // Receive a packet into the buffer.
        ssize_t data_size = recvfrom(sockfd, buffer, sizeof(buffer), 0, NULL, NULL);

        if (data_size < 0) {
            perror("Packet receive error");
            close(sockfd);
            exit(1);
        }

        // Extract the IP header and TCP header from the received packet.
        struct ip* ip_header = (struct ip*)buffer;
        struct tcphdr* tcp_header = (struct tcphdr*)(buffer + ip_header->ip_hl * 4);

        char source_ip[INET_ADDRSTRLEN];
        char dest_ip[INET_ADDRSTRLEN];

        // Convert source and destination IP addresses to human-readable form.
        inet_ntop(AF_INET, &(ip_header->ip_src), source_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), dest_ip, INET_ADDRSTRLEN);

        // Get source and destination port numbers.
        int source_port = ntohs(tcp_header->th_sport);
        int dest_port = ntohs(tcp_header->th_dport);

        // Print the captured packet information.
        printf("Source IP: %s, Source Port: %d, Dest IP: %s, Dest Port: %d\n",
               source_ip, source_port, dest_ip, dest_port);
    }

    // Close the socket when done.
    close(sockfd);

    return 0;
}