// Linux-Based Network Packet Analyzer
// Captures live traffic on a network interface in promiscuous mode using
// libpcap, then manually parses Ethernet, IPv4, TCP, and UDP headers via
// structured memory mapping over the raw bytes.
//
// Build:  make
// Run:    sudo ./packet_analyzer [interface]
//
// Requires: libpcap-dev (Linux), root privileges for live capture.

#include <pcap.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <netinet/in.h>
#include <arpa/inet.h>

// ---------------------------------------------------------------------------
// Protocol header layouts, mapped directly onto the raw packet bytes.
// __attribute__((packed)) removes compiler padding so each struct matches
// the exact on-the-wire byte layout.
// ---------------------------------------------------------------------------

struct __attribute__((packed)) EthernetHeader {
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    uint16_t ether_type;   // network byte order
};

struct __attribute__((packed)) IPv4Header {
    uint8_t  version_ihl;      // upper nibble: version, lower nibble: IHL (in 32-bit words)
    uint8_t  tos;
    uint16_t total_length;
    uint16_t id;
    uint16_t flags_fragment;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;
    uint32_t dst_addr;
};

struct __attribute__((packed)) TCPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  data_offset_reserved; // upper nibble: data offset in 32-bit words
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
};

struct __attribute__((packed)) UDPHeader {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

static const int ETHERNET_HEADER_LEN = sizeof(EthernetHeader);
static const uint16_t ETHERTYPE_IPV4 = 0x0800;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// ---------------------------------------------------------------------------
// Per-packet callback invoked by pcap_loop for every captured frame.
// ---------------------------------------------------------------------------

static void packet_handler(u_char *user_args, const struct pcap_pkthdr *header,
                            const u_char *packet) {
    (void)user_args;
    static long packet_count = 0;
    packet_count++;

    printf("\n================= Packet #%ld =================\n", packet_count);

    time_t ts = header->ts.tv_sec;
    char time_buf[32];
    struct tm *tm_info = localtime(&ts);
    strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm_info);
    printf("Time: %s.%06ld | Captured: %u bytes | On-wire: %u bytes\n",
           time_buf, (long)header->ts.tv_usec, header->caplen, header->len);

    // ---- Ethernet layer ----
    if (header->caplen < (uint32_t)ETHERNET_HEADER_LEN) {
        printf("  [!] Frame too short to contain an Ethernet header.\n");
        return;
    }

    const EthernetHeader *eth = reinterpret_cast<const EthernetHeader *>(packet);
    uint16_t ether_type = ntohs(eth->ether_type);

    printf("Ethernet | Src: ");
    print_mac(eth->src_mac);
    printf(" -> Dst: ");
    print_mac(eth->dest_mac);
    printf(" | EtherType: 0x%04x\n", ether_type);

    if (ether_type != ETHERTYPE_IPV4) {
        printf("  [-] Non-IPv4 EtherType, skipping L3/L4 parsing.\n");
        return;
    }

    // ---- IPv4 layer ----
    const u_char *ip_start = packet + ETHERNET_HEADER_LEN;
    if (header->caplen < (uint32_t)(ETHERNET_HEADER_LEN + (int)sizeof(IPv4Header))) {
        printf("  [!] Frame too short to contain an IPv4 header.\n");
        return;
    }

    const IPv4Header *ip = reinterpret_cast<const IPv4Header *>(ip_start);
    uint8_t ip_version    = (ip->version_ihl >> 4) & 0x0F;
    uint8_t ip_header_len = (ip->version_ihl & 0x0F) * 4;   // dynamic offset: ip_hl * 4

    if (ip_version != 4) {
        printf("  [!] Unexpected IP version %d, expected IPv4.\n", ip_version);
        return;
    }
    if (ip_header_len < 20) {
        printf("  [!] Invalid IPv4 header length (%d bytes).\n", ip_header_len);
        return;
    }

    struct in_addr src_ip{}, dst_ip{};
    src_ip.s_addr = ip->src_addr;
    dst_ip.s_addr = ip->dst_addr;

    printf("IPv4     | %s -> %s | IHL: %d bytes | TTL: %d | Total Len: %d | Proto: %d\n",
           inet_ntoa(src_ip), inet_ntoa(dst_ip), ip_header_len, ip->ttl,
           ntohs(ip->total_length), ip->protocol);

    // ---- Transport layer (offset computed dynamically from IHL) ----
    const u_char *transport_start = ip_start + ip_header_len;
    if (header->caplen < (uint32_t)(ETHERNET_HEADER_LEN + ip_header_len)) {
        printf("  [!] Frame too short for declared IPv4 header length.\n");
        return;
    }
    uint32_t remaining = header->caplen - (ETHERNET_HEADER_LEN + ip_header_len);

    switch (ip->protocol) {
        case IPPROTO_TCP: {
            if (remaining < sizeof(TCPHeader)) {
                printf("  [!] Frame too short for a TCP header.\n");
                return;
            }
            const TCPHeader *tcp = reinterpret_cast<const TCPHeader *>(transport_start);
            printf("TCP      | Port %u -> %u | Seq: %u | Ack: %u | Flags: 0x%02x\n",
                   ntohs(tcp->src_port), ntohs(tcp->dst_port),
                   ntohl(tcp->seq_num), ntohl(tcp->ack_num), tcp->flags);
            break;
        }
        case IPPROTO_UDP: {
            if (remaining < sizeof(UDPHeader)) {
                printf("  [!] Frame too short for a UDP header.\n");
                return;
            }
            const UDPHeader *udp = reinterpret_cast<const UDPHeader *>(transport_start);
            printf("UDP      | Port %u -> %u | Length: %u\n",
                   ntohs(udp->src_port), ntohs(udp->dst_port), ntohs(udp->length));
            break;
        }
        default:
            printf("Transport| Protocol %d (not TCP/UDP), skipping port parsing.\n",
                   ip->protocol);
    }
}

// ---------------------------------------------------------------------------
// Entry point: selects an interface, opens it in promiscuous mode, and
// hands every captured frame to packet_handler.
// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev_storage;
    const char *dev = nullptr;

    if (argc == 2) {
        dev = argv[1];
    } else {
        pcap_if_t *alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) {
            fprintf(stderr, "Error listing devices: %s\n", errbuf);
            return EXIT_FAILURE;
        }
        if (alldevs == nullptr) {
            fprintf(stderr, "No capture devices found. Are you root?\n");
            return EXIT_FAILURE;
        }
        dev_storage = alldevs->name;
        dev = dev_storage.c_str();
        printf("No interface given, defaulting to: %s\n", dev);
        pcap_freealldevs(alldevs);
    }

    printf("Opening %s in promiscuous mode...\n", dev);
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, /*promisc=*/1, /*timeout_ms=*/1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Failed to open device %s: %s\n", dev, errbuf);
        fprintf(stderr, "Hint: live capture usually requires sudo / CAP_NET_RAW.\n");
        return EXIT_FAILURE;
    }

    // Only capture Ethernet + IPv4 links for this analyzer.
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "Device %s does not provide Ethernet headers.\n", dev);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

    printf("Listening on %s. Press Ctrl+C to stop.\n", dev);
    pcap_loop(handle, /*count=*/0, packet_handler, nullptr);

    pcap_close(handle);
    return EXIT_SUCCESS;
}
