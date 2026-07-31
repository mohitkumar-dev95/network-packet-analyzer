# Linux-Based Network Packet Analyzer

A real-time network packet sniffing tool written in C++ using `libpcap`.
It captures live traffic on a Linux network interface in promiscuous mode
and manually parses raw Ethernet frames, IPv4 headers, and TCP/UDP segment
headers via structured memory mapping over the captured bytes.

## Features

- Live packet capture on any interface using `libpcap` in promiscuous mode.
- Low-level Ethernet frame parsing (source/destination MAC, EtherType).
- IPv4 header parsing with **dynamic header offset calculation**
  (`ip_hl * 4`) to correctly handle variable-length IPv4 headers (with or
  without options).
- TCP and UDP segment header parsing, extracting source/destination ports.
- Proper network-to-host byte order conversion (`ntohs` / `ntohl`) for
  cross-platform correctness.
- Bounds checking at every layer to avoid reading past the captured buffer.

## Requirements

- Linux
- `g++` with C++17 support
- `libpcap-dev`

Install dependencies on Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y build-essential libpcap-dev
```

## Build

```bash
make
```

## Run

Live packet capture requires raw socket access, so run as root (or grant
the binary `CAP_NET_RAW`/`CAP_NET_ADMIN`):

```bash
sudo ./packet_analyzer            # capture on the default interface
sudo ./packet_analyzer eth0       # capture on a specific interface
```

Or via the Makefile:

```bash
make run
```

Stop capture with `Ctrl+C`.

## Example Output

```
================= Packet #1 =================
Time: 2026-07-31 06:20:11.482113 | Captured: 74 bytes | On-wire: 74 bytes
Ethernet | Src: aa:bb:cc:dd:ee:ff -> Dst: 11:22:33:44:55:66 | EtherType: 0x0800
IPv4     | 192.168.1.10 -> 142.250.72.14 | IHL: 20 bytes | TTL: 64 | Total Len: 60 | Proto: 6
TCP      | Port 51422 -> 443 | Seq: 123456789 | Ack: 0 | Flags: 0x02
```

## How It Works

1. `pcap_open_live()` opens the chosen interface in promiscuous mode so the
   NIC delivers all frames it sees, not just ones addressed to this host.
2. `pcap_loop()` invokes a callback for every captured frame.
3. The callback overlays `struct` definitions (`EthernetHeader`,
   `IPv4Header`, `TCPHeader`, `UDPHeader`), each marked
   `__attribute__((packed))`, directly onto the raw byte buffer instead of
   copying data — this is the "structured memory mapping" approach.
4. The IPv4 header's Internet Header Length (IHL) field is read and
   multiplied by 4 to compute the *actual* header size, since IPv4 headers
   are variable-length when options are present. This offset is then used
   to locate the start of the TCP/UDP payload correctly.
5. All multi-byte header fields are converted from network byte order
   (big-endian) to host byte order with `ntohs()` (16-bit) and `ntohl()`
   (32-bit) before being printed.

## Project Structure

```
network-packet-analyzer/
├── src/
│   └── main.cpp     # capture loop + header parsing logic
├── Makefile
├── README.md
└── .gitignore
```

## Concepts Demonstrated

- OSI layer mapping (Data Link, Network, Transport)
- Raw socket / libpcap-based packet capture
- Manual protocol header parsing without external parsing libraries
- Byte-order (endianness) handling
- Socket-level data flow

## License

MIT
