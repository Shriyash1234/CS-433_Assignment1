#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// Structure to represent a unique TCP flow tuple
struct TCPFlow {
    char client_ip[INET_ADDRSTRLEN];
    char server_ip[INET_ADDRSTRLEN];
    uint16_t client_port;
    uint16_t server_port;
};

// Compare function for TCP flow tuples
int compare_flow(const void *a, const void *b) {
    const struct TCPFlow *flow_a = (const struct TCPFlow *)a;
    const struct TCPFlow *flow_b = (const struct TCPFlow *)b;

    int cmp = strcmp(flow_a->client_ip, flow_b->client_ip);
    if (cmp == 0) {
        cmp = flow_a->client_port - flow_b->client_port;
        if (cmp == 0) {
            cmp = strcmp(flow_a->server_ip, flow_b->server_ip);
            if (cmp == 0) {
                cmp = flow_a->server_port - flow_b->server_port;
            }
        }
    }
    return cmp;
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the network interface "eth0" for packet capture
    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Error opening interface: %s\n", errbuf);
        return 1;
    }

    // Array to store unique TCP flow tuples
    struct TCPFlow flow_list[2048];  // Assuming a maximum of 1024 unique flows
    int flow_count = 0;

    while (true) {
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);

        if (packet == NULL) {
            continue;  // If no packet is available, continue the loop
        }

        // Extract IP and TCP headers from the packet
        struct ip *ip_header = (struct ip *)(packet + 14);
        struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header->ip_hl * 4);

        // Extract the flow tuple from the packet
        struct TCPFlow current_flow;
        inet_ntop(AF_INET, &(ip_header->ip_src), current_flow.client_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(ip_header->ip_dst), current_flow.server_ip, INET_ADDRSTRLEN);
        current_flow.client_port = ntohs(tcp_header->th_sport);
        current_flow.server_port = ntohs(tcp_header->th_dport);

        // Check if the flow is already in the list of unique flows
        bool flow_exists = false;
        for (int i = 0; i < flow_count; i++) {
            if (compare_flow(&flow_list[i], &current_flow) == 0) {
                flow_exists = true;
                break;  // Flow already exists, so no need to add it again
            }
        }

        if (!flow_exists) {
            // Add the new flow to the list of unique flows
            flow_list[flow_count] = current_flow;
            flow_count++;

            // Print the flow information and the current flow count
            printf("Flow Count: %d, Client IP: %s, Client Port: %d, Server IP: %s, Server Port: %d\n",
                   flow_count, current_flow.client_ip, current_flow.client_port,
                   current_flow.server_ip, current_flow.server_port);
        }
    }

    // Close the pcap handle when the program exits
    pcap_close(handle);
    return 0;
}
