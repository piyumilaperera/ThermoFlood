<div align="center">

# ThermoFlood

**A high-performance SYN Flood Network Stress Testing Tool, built for low-level protocol research and security analysis.**

![C](https://img.shields.io/badge/Language-C-blue?style=flat-square&logo=c)
![Platform](https://img.shields.io/badge/Platform-Linux-informational?style=flat-square&logo=linux)
![Security](https://img.shields.io/badge/Category-Network%20Security-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-1.0.0-green?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)

*Harnesses raw sockets and multi-threading to simulate heavy TCP SYN traffic with full IP spoofing capabilities.*

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [How It Works](#-how-it-works)
- [Technical Deep Dive](#-technical-deep-dive)
- [Compilation](#-compilation)
- [Usage](#-usage)
- [Issues & Limitations](#-issues--limitations)
- [Disclaimer](#-disclaimer)

---

## 🔍 Overview

**ThermoFlood** is a network security tool written in C that demonstrates the mechanics of a **TCP SYN Flood**. Unlike standard networking tools that rely on the OS kernel to handle handshakes, ThermoFlood utilizes **Raw Sockets (`SOCK_RAW`)** to manually construct every bit of the IP and TCP headers. 

Named after the famous battle where a small force held back a massive one, this tool is designed to test the resilience of network infrastructure against resource exhaustion attacks.


<p align="center">
  <img src="https://github.com/piyumilaperera/ThermoFlood/blob/main/media/images/1. Introduction.png"></p>


### What is a SYN Flood?

In a normal TCP connection, a "Three-Way Handshake" occurs. An attacker sends multiple SYN (Synchronize) packets but never responds to the server's SYN-ACK, leaving the server with "half-open" connections that eventually exhaust its resources.

| Phase | Packet Type | Action |
|-------|-------------|--------|
| 1     | **SYN** | Client requests connection (ThermoFlood sends this) |
| 2     | **SYN-ACK** | Server acknowledges and waits |
| 3     | **ACK** | Client completes handshake (Ignored in a flood) |

---

## ⚙️ How It Works

ThermoFlood bypasses the standard TCP/IP stack by using the `IPPROTO_RAW` protocol. This tells the kernel: *"Don't touch my headers; I am providing them myself."* The Checksum Challenge
One of the most complex parts of this tool is calculating the **TCP Checksum**. The TCP protocol requires a **Pseudo Header** for this calculation, which includes fields from the IP header that aren't actually in the TCP segment itself. This ensures that the packet is technically valid and will be accepted by the target's network stack.

---

## 💻 Technical Deep Dive

### Header Structures
The tool uses standard Linux headers (`<netinet/ip.h>` and `<netinet/tcp.h>`) to map the packet structure:

* **IP Header (`struct iphdr`):** Defines the version (IPv4), Time-to-Live (TTL), and Source/Destination IP addresses.
* **TCP Header (`struct tcphdr`):** Defines the ports, Sequence numbers, and the `syn` flag bit.

### The Pseudo-Header
Because the TCP checksum calculation must include the source and destination IPs to ensure the packet hasn't been misrouted, we use a custom struct:

```c
typedef struct pseudo_header
{
    u_int32_t source_address;
    u_int32_t destination_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t tcp_length;
} pseudo_header;
```

### Multi-threading Logic

To achieve maximum throughput, the tool implements a thread-per-socket model using pthread. Each thread creates its own raw socket descriptor and loops the sendto function, significantly increasing the Packets Per Second (PPS) count compared to a single-threaded approach.

---

## 🚀 Compilation
Prerequisites :- 

  * GCC compiler (gcc)

  * Linux Environment (Raw sockets require Linux-specific headers)

  * Root/Sudo Privileges (Required for SOCK_RAW)

  ```
  # Compile with the pthread library linked
gcc ThermoFlood.c -o ThermoFlood -lpthread
```

---

 
## 🛠 Usage

Since the tool interacts directly with the network interface and creates raw sockets, it must be run with sudo.

```
sudo ./ThermoFlood
```
Setup Flow :- 

  * Source IP: Enter the IP you wish to appear as (Supports Spoofing).

  * Source Port: Choose the origin port for the SYN packets.

  * Destination IP: The target server's IP address.

  * Destination Port: The service port (e.g., 80 for HTTP, 443 for HTTPS).


### Perform an attack without spoof the ip

<p align="center">It's successfully sent packets to the target machine</p>

<p align="center">
  <img src="https://github.com/piyumilaperera/ThermoFlood/blob/main/media/images/2. Flood_without_spoofing.png"></p>



<p align="center">We can confirm it by looking at the graph</p>

<p align="center">
  <img src="https://github.com/piyumilaperera/ThermoFlood/blob/main/media/images/3. Flood_without_spoofing.png"></p>

### Perform an attack with ip spoofing

<p align="center">Now i am spoofed my ip, pay attention to my real ip and the spoofed one</p>

<p align="center">
  <img src="https://github.com/piyumilaperera/ThermoFlood/blob/main/media/images/4. Flood_with_spoofing.png"></p>




  <p align="center">It's successfully sent packets to the target machine</p>

<p align="center">
  <img src="https://github.com/piyumilaperera/ThermoFlood/blob/main/media/images/5. Flood_with_spoofing.png"></p>

  ---

## ⚠️ Issues & Limitations


1. Root Necessity
Construction of raw headers requires CAP_NET_RAW capabilities, typically only available to the root user.

2. Modern Mitigation
Many modern firewalls and ISPs use SYN Cookies or ingress filtering (BCP 38) which can detect and drop spoofed packets or mitigate the flood's impact.

3. Sequence Numbers
Current version (v1.0.0) uses static sequence numbers. Future updates will implement randomization for better simulation.

4. Platform Support
Tested on Debian-based Linux (Pop!_OS). Direct raw socket manipulation is highly platform-dependent and may require modifications for BSD or macOS due to differences in how the IPPROTO_RAW socket handles header offsets.

---

## 💬 Future Expectations

1. Avoid the fixed packet structure.

2. randomization of source ports, sequence numbers and TTL values.

3. Emplement a mac spoof feature.

---

## ⚖️ Disclaimer

ThermoFlood
 is for educational and authorized testing purposes only. Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical. The developer, Piyumila Perera, assumes no liability for misuse or damage caused by this software. Use it to learn, to defend, and to understand the architecture of the web, not to destroy.

---


<div align="center">

Developed by Piyumila Perera  |  Network Security Research  |  v1.0.0

Exploring the depths of the OSI model, one packet at a time.

</div>
