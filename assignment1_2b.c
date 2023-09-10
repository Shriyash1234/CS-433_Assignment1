#include <stdio.h>
#include <string.h>
#include <pcap.h>

// This function is called for each packet in the pcap file
void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // Define the search string we want to find in the packet
    char *search_string = "username=secret";

    // Convert the packet data to a character array
    char *data = (char *)packet;

    // Get the length of the packet data
    int data_len = pkthdr->len;

    // Search for the search_string in the packet data
    for (int i = 0; i < data_len - strlen(search_string); i++) {
        if (strncmp(data + i, search_string, strlen(search_string)) == 0) {
            // If the search_string is found, print the matched portion of the packet data
            printf("%.*s\n", data_len - i, data + i);
            return; // Exit the loop after finding the first occurrence
        }
    }
}

int main(int argc, char *argv[]) {
    // Check if the correct number of arguments is provided
    if (argc != 2) {
        printf("Enter name of .pcap file after");
        return 1; // Exit with an error code if incorrect arguments are provided
    }

    // Get the filename of the pcap file from the command-line arguments
    char *filename = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Open the pcap file for reading
    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        // Print an error message if opening the file fails
        fprintf(stderr, "Error opening pcap file: %s\n", errbuf);
        return 1; // Exit with an error code
    }

    // Start processing packets from the pcap file using the packet_handler function
    if (pcap_loop(handle, 0, packet_handler, NULL) < 0) {
        // Print an error message if an error occurs during packet processing
        fprintf(stderr, "Error in pcap_loop()\n");
        return 1; // Exit with an error code
    }

    // Close the pcap file when processing is complete
    pcap_close(handle);

    return 0; // Exit with a success code
}
