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
sudo ./packet_analyzer                              # capture on the default interface
sudo ./packet_analyzer -i eth0                       # capture on a specific interface
sudo ./packet_analyzer -i eth0 -f "tcp port 443"      # apply a BPF filter
sudo ./packet_analyzer -w capture.pcap                # also save to a .pcap file (Wireshark-compatible)
sudo ./packet_analyzer -i wlan0 -f "udp" -w udp.pcap  # combine interface + filter + dump
```

| Flag | Description |
|------|-------------|
| `-i <iface>` | Interface to capture on (default: first available) |
| `-f "<expr>"` | BPF filter expression, e.g. `"tcp port 443"`, `"udp"`, `"host 8.8.8.8"` |
| `-w <file>` | Write captured packets to a `.pcap` file you can open in Wireshark |
| `-h` | Show usage |

Stop capture with `Ctrl+C` — this triggers a clean shutdown via
`pcap_breakloop()` and prints a summary of total packets captured, broken
down by TCP / UDP / other IPv4 / non-IPv4.

## Example Output

```
================= Packet #1 =================
Time: 2026-07-31 06:20:11.482113 | Captured: 74 bytes | On-wire: 74 bytes
Ethernet | Src: aa:bb:cc:dd:ee:ff -> Dst: 11:22:33:44:55:66 | EtherType: 0x0800
IPv4     | 192.168.1.10 -> 142.250.72.14 | IHL: 20 bytes | TTL: 64 | Total Len: 60 | Proto: 6
TCP      | Port 51422 -> 443 | Seq: 123456789 | Ack: 0 | Flags: 0x02
```

```
================= Capture Summary =================
Total packets : 1
  TCP         : 1
  UDP         : 0
  Other IPv4  : 0
  Non-IPv4    : 0
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
6. An optional BPF filter (`-f`) is compiled with `pcap_compile()` and
   applied with `pcap_setfilter()` so the kernel does the filtering before
   packets even reach userspace.
7. An optional `.pcap` dump file (`-w`) is written alongside the console
   output using `pcap_dump()`, so captured traffic can be reopened later in
   Wireshark or any other pcap-compatible tool.
8. A `SIGINT` handler calls `pcap_breakloop()` on `Ctrl+C` for a clean stop
   (rather than being killed mid-packet), then prints a per-protocol
   summary before exiting.

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

## Relevance

This project demonstrates several fundamentals commonly required for
Linux/embedded/networking software roles (SWE positions):

- **C/C++ on Linux** — no external parsing libraries; headers are decoded
  by hand over raw memory.
- **Protocols** — Ethernet, IPv4, TCP, UDP parsed directly from the wire
  format, including correct network-to-host byte-order conversion
  (`ntohs()` / `ntohl()`).
- **OS/socket-level concepts** — promiscuous-mode capture, OSI layer
  mapping, structured memory mapping over raw buffers.

Note: this operates entirely in **userspace** via `libpcap` — it is not a
kernel driver or firmware component.

## License

MIT
