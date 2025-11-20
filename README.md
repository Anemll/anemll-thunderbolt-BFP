# anemll-thunderbolt-BFP

Goal
----
The goal of this project is to test low-latency Thunderbolt 4/5 (TB4/TB5) communications by bypassing the TCP/IP stack on the receiver using BPF (Berkeley Packet Filter). This approach allows for precise latency measurements and reduced jitter by operating at the raw Ethernet frame level, avoiding kernel network stack overhead.

Purpose
-------
This project contains a tool to test low-latency Thunderbolt 4/5 (TB4/TB5) networking links using UDP over Berkeley Packet Filter. It is designed to measure RTT (latency) and throughput, and to provide a low-jitter testing path by bypassing the kernel network stack when desired.

Why BPF / libpcap?
------------------
- "BPF/pcap mode" (using libpcap to send/receive full Ethernet frames) allows constructing and injecting raw Ethernet/IP/UDP frames directly on the wire.
- Running in BPF mode bypasses parts of the kernel's UDP/TCP stack, socket buffers and scheduling behavior — which often reduce and stabilize latency and reduce jitter.
- In some setups we observed reductions on the order of 50–80 microseconds and more stable latency distributions when operating the test in BPF/pcap mode compared to normal UDP sockets.

Important: keeping the network fast
-----------------------------------
What I discovered in testing: to keep the network interface and any NIC/bridge/forwarding hardware in a fast steady-state and maintain low latency, it's important to maintain a relatively high packet rate. If the hardware or drivers can enter a lower power or less-responsive state at low traffic, bursts and low average rates can increase latency variance. For realistic low-latency testing you should:
- Drive a steady packet rate (higher pps) rather than sending very sparse packets.
- Use batch ACKing and tune batch sizes to match the network capacity and desired measurement granularity.

Requirements & Platform notes
----------------------------
- Platform: Primarily macOS. The code uses macOS-specific mach time APIs and certain socket options (IP_BOUND_IF).
- Compiler: clang++ with C++17 support.
- Build: libpcap is required for BPF/pcap mode. On macOS install libpcap via package manager if needed (e.g., Homebrew).
- Permissions: BPF/pcap mode typically requires elevated privileges (root/sudo) to capture and inject raw frames. Normal UDP mode (-u) can run without root.
- Porting: To run on Linux you'll need to adapt the time source (mach_* calls) and BPF device handling — the code is macOS-oriented.

Build
-----
Example build command:
```
clang++ -std=c++17 -O2 -pthread main.cpp -lpcap -o udp_tbolt_tester
```

Usage examples
--------------
Start server on interface en5, port 8888 (pcap/BPF mode; typically requires sudo):
```
sudo ./udp_tbolt_tester -s -i en5 -p 8888
```

Client → 192.168.2.2, sending 2000 pps of 1400-byte payloads, using normal UDP sockets:
```
./udp_tbolt_tester -c 192.168.2.2 -i en5 -r 2000 -z 1400 -u
```

Key flags
---------
- -s               server (responder) mode
- -c <addr>        destination IPv4 address (client only)
- -p <port>        UDP port (default 8888)
- -i <ifname>      bind to network interface (macOS)
- -r <rate>        send rate in packets/second (client, default 1000)
- -z <bytes>       payload size excluding 20‑byte header (default 128)
- -t <timeout_us>  ACK timeout in microseconds (client)
- -d <seconds>     total runtime (0 = unlimited)
- -m <max_in_flight> maximum packets in flight (client)
- -b <batch_size>  number of packets to batch in one ACK
- -v               verbose (per‑packet log)
- -u               use normal UDP sockets instead of BPF (no root required)
- -n               no ACK mode (send continuously, ignore ACKs)
- -n2              continuous send mode (send without waiting but still process ACKs)
- -x               skip UDP socket initialization (pcap/BPF-only)
- -D               use distinct source ports (pcap/BPF mode)

Libpcap and architecture notes
------------------------------
- The BPF/pcap mode sends full frames using `pcap_sendpacket` and receives using `pcap_next_ex`.
- This provides precise control over source MAC, source port, and frame structure so the test can avoid kernel buffering and scheduling artifacts.
- The README and source include details on the built-in packet Header structure used for measurements.
- BPF/pcap mode is the preferred mode for strict low-latency tests where the kernel path introduces unacceptable jitter.

Troubleshooting
---------------
- If you see permission errors while using BPF/pcap mode, run with `sudo` or adjust pcap/device permissions.
- If pcap filters are not matching traffic, check the interface name and the host IP used for filtering.
- If RTT numbers look incorrect for batched ACKs, check the code TODO regarding the server selecting the correct send_ns for the batch; it may need refinement.

Testing
-------
### Quick compilation test
```bash
clang++ -std=c++17 -O2 -pthread main.cpp -lpcap -o udp_tbolt_tester
./udp_tbolt_tester  # Should display help message
```

### Loopback testing (localhost)
**Note:** Server requires `sudo` for BPF/pcap mode. Client can use UDP mode (`-u`) without root.

**Terminal 1 (Server):**
```bash
sudo ./udp_tbolt_tester -s -i lo0 -p 8888
```

**Terminal 2 (Client):**
```bash
./udp_tbolt_tester -c 127.0.0.1 -i lo0 -p 8888 -u -r 1000 -z 128 -d 5
```

Expected output: Client should show RTT statistics and throughput. Server will display received packet rates and bandwidth.

### Real network interface testing
Find your network interface:
```bash
ifconfig | grep "^[a-z]" | grep -v lo0
```

**Terminal 1 (Server on interface en5):**
```bash
sudo ./udp_tbolt_tester -s -i en5 -p 8888
```

**Terminal 2 (Client to server IP 192.168.2.2):**
```bash
./udp_tbolt_tester -c 192.168.2.2 -i en5 -p 8888 -r 2000 -z 1400 -u -d 10
```

### Verification checklist
- ✓ Compilation succeeds without errors
- ✓ Help message displays when run without arguments
- ✓ Server starts and waits for packets
- ✓ Client connects and sends packets
- ✓ RTT statistics appear in client output
- ✓ Server shows received packet rates

License
-------
This project is licensed under the MIT License. See the LICENSE file for details.

Contact / Contribution
----------------------
Open issues or PRs on the repository for fixes, improvements, or platform ports (Linux).