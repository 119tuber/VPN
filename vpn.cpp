#include <iostream>
#include <pcap.h>
// #include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <cstring>
#include <unistd.h>

// Define the iphdr structure for macOS
struct iphdr {
    unsigned int ihl : 4;   // Header length
    unsigned int version : 4; // Version
    uint8_t tos;            // Type of service
    uint16_t tot_len;       // Total length
    uint16_t id;            // Identification
    uint16_t frag_off;      // Fragment offset field
    uint8_t ttl;            // Time to live
    uint8_t protocol;       // Protocol
    uint16_t check;         // Checksum
    uint32_t saddr;         // Source address
    uint32_t daddr;         // Destination address
};

// Function to calculate checksum
unsigned short calculate_checksum(unsigned short *buf, int len) {
    unsigned long sum = 0;
    while (len > 1) {
        sum += *buf++;
        len -= 2;
    }
    if (len == 1) {
        sum += *(unsigned char *)buf;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return ~sum;
}

// Function to modify and send a captured packet
void modify_and_send_packet(const u_char *packet, int packet_len) {
    // Create raw socket
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sock < 0) {
        perror("Raw socket creation failed");
        return;
    }

    // Ensure packet length is within buffer size
    if (packet_len > 4096) {
        std::cerr << "Packet size exceeds buffer limit" << std::endl;
        close(sock);
        return;
    }

    // Copy the original packet
    char modified_packet[4096];
    memcpy(modified_packet, packet, packet_len);

    // Modify the source IP in the IP header
    struct iphdr *ip_header = (struct iphdr *)modified_packet;
    ip_header->saddr = inet_addr("192.168.1.100");  // Spoofed source IP

    // Recalculate the IP checksum
    ip_header->check = 0;  // Reset checksum before recalculating
    ip_header->check = calculate_checksum((unsigned short *)ip_header, ip_header->ihl * 4);

    // Destination address structure
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = ip_header->daddr;

    // Send the modified packet
    if (sendto(sock, modified_packet, packet_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) < 0) {
        perror("Packet send failed");
    } else {
        std::cout << "Packet sent successfully!" << std::endl;
    }

    close(sock);
}

// Callback function for packet capture
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    std::cout << "Captured a packet!" << std::endl;
    modify_and_send_packet(packet, header->len);
}

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Ensure the user specifies a network interface
    if (argc < 2) {
        std::cerr << "Usage: " << argv[0] << " <network_interface>" << std::endl;
        return 1;
    }

    // Open live capture on the specified network interface
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "pcap_open_live failed: " << errbuf << std::endl;
        return 1;
    }

    std::cout << "Listening on interface: " << argv[1] << std::endl;

    // Start capturing packets
    if (pcap_loop(handle, -1, packet_handler, nullptr) < 0) {
        std::cerr << "pcap_loop failed: " << pcap_geterr(handle) << std::endl;
        pcap_close(handle);
        return 1;
    }

    pcap_close(handle);
    return 0;
}
