//
// anemll-thunderbolt-BFP — UDP / Thunderbolt low-latency tester (main.cpp)
//
// Purpose
//   Small utility to measure latency (RTT) and throughput over a Thunderbolt
//   network link (TB4/TB5). Supports two send/receive modes:
//     - BPF/pcap mode: craft and inject full Ethernet/IP/UDP frames via libpcap.
//       This bypasses the kernel UDP/TCP stack and can lower and stabilize
//       latency (typical observed improvements: 50–80 microseconds in some setups).
//     - Normal UDP sockets: use the kernel UDP stack (easier to run without root).
//
//   BPF/pcap mode is intended to keep latency low and stable by avoiding kernel
//   queuing, offloads, and scheduling jitter that can occur in the kernel
//   network stack. In practice, to keep the link fast and latency stable you
//   should keep a high packet rate (sustained load) so that link/forwarding
//   hardware stays in a fast steady-state (avoids autosleep transitions).
//
// Build
//   clang++ -std=c++17 -O2 -pthread main.cpp -lpcap -o udp_tbolt_tester
//
// Notes
//  - Designed for macOS (uses mach_absolute_time and IP_BOUND_IF options).
//  - BPF/pcap mode usually requires root privileges (pcap injection, raw frames).
//  - libpcap is required for BPF/pcap mode (pcap_sendpacket/pcap_next_ex).
//  - Keep an eye on the caveats: some ACK timestamp selection logic has TODOs
//    in the code and may need refinement for exact RTT accounting in batched ACKs.
//
// Packet header (little-endian)
//   const uint32_t MAGIC = 0x414E4D31; // "ANM1"
//   struct Header {
//       uint32_t magic;        // must equal MAGIC
//       uint32_t seq;          // monotonically increasing sequence id (data) or 0 for ACK
//       uint32_t payload_len;  // payload size in bytes (0 for ACK)
//       uint32_t type;         // 0=data, 1=ack, 2=nak
//       uint64_t send_ns;      // client send timestamp (ns) or batch send ns for ACKs
//       uint32_t ack_count;    // number of sequences included in ACK
//       uint16_t batch_size;   // client's desired batch size
//       uint16_t no_in_batch;  // position in client batch
//       uint32_t ack_seqs[];   // variable-length list of acknowledged seq numbers
//   } __attribute__((packed));
//
// License: MIT (see LICENSE file in repository)
// Author: ANEMLL
//

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <net/if_dl.h>  // For LLADDR
#include <net/if_arp.h> // For ARPHRD_ETHER
#include <net/if_types.h> // For IFT_ETHER
#include <pthread.h> // For thread priority
#include <sched.h>   // For scheduling parameters
#include <mach/mach_time.h> // For mach_absolute_time

#include <algorithm>
#include <chrono>
#include <deque>
#include <iomanip>
#include <iostream>
#include <map>
#include <numeric>
#include <string>
#include <thread>
#include <vector>
#include <mutex>
#include <optional>
#include <atomic> // Include for std::atomic

using Clock = std::chrono::steady_clock;
using ns    = std::chrono::nanoseconds;
using ms    = std::chrono::milliseconds;
using us    = std::chrono::microseconds;

constexpr uint32_t MAGIC = 0x414E4D31; // "ANM1"
// Timeout for considering a packet lost (1ms)
constexpr uint64_t PACKET_TIMEOUT_NS = 20 * 1000 * 1000ull;
// Define distinct ports for -d flag
// REMOVED: constexpr uint16_t CLIENT_SRC_PORT_DISTINCT = 9901;
// REMOVED: constexpr uint16_t SERVER_SRC_PORT_DISTINCT = 9902;

// Minimum ACK sending rate constants
constexpr uint32_t MIN_ACK_RATE_PPS = 5000; // Minimum ACKs per second
constexpr uint64_t MIN_ACK_INTERVAL_NS = (MIN_ACK_RATE_PPS > 0) ? (1'000'000'000ull / MIN_ACK_RATE_PPS) : 0;
constexpr uint64_t MAX_IDLE_TIME_BEFORE_FORCE_ACK_NS = 1'000'000'000ull; // 1 second

// IP header structure
struct iphdr {
    uint8_t version:4;
    uint8_t ihl:4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
} __attribute__((packed));

// Use system's udphdr instead of redefining
// struct udphdr {
//     uint16_t uh_sport;    // source port
//     uint16_t uh_dport;    // destination port
//     uint16_t uh_ulen;     // udp length
//     uint16_t uh_sum;      // udp checksum
// } __attribute__((packed));

struct Header {
    uint32_t magic;
    uint32_t seq;
    uint32_t payload_len;
    uint32_t type;  // 0: data, 1: ack, 2: nak
    uint64_t send_ns;
    uint32_t ack_count;  
    uint16_t batch_size; 
    uint16_t no_in_batch;  // from 0 to batch_size - 1   
    uint32_t ack_seqs[0];  //
} __attribute__((packed));

constexpr size_t HEADER_SIZE = sizeof(Header); // 20 bytes
constexpr size_t MAX_WINDOW  = 100;            // history size for dup/loss detection
constexpr size_t RTT_WINDOW  = 256;            // rolling RTT stats
constexpr size_t MAX_PAYLOAD = 8930;           // arbitrary cap
#define MIN_ACK_SIZE MAX_PAYLOAD             // Pad ACK UDP payload to this size if > 0
constexpr size_t MAX_IN_FLIGHT = 1000;         // maximum packets in flight

// Base statistics structure
struct Stats {
    // All-time totals
    uint64_t sent = 0;
    uint64_t acks = 0;
    uint64_t dup  = 0;  // Note: Dup detection likely needs server-side logic
    uint64_t lost = 0;  // Note: Loss detection needs refinement
    uint64_t dropped = 0; // Client-side drops if window is full (if implemented)
    
    // All-time RTT stats
    double rtt_avg_ns = 0.0;
    double rtt_min_ns = 1e18;
    double rtt_max_ns = 0.0;
    uint64_t rtt_samples = 0;
    
    // Current Interval Stats (for periodic reporting)
    uint64_t sent_current = 0;
    uint64_t acks_current = 0;
    // uint64_t lost_current = 0; // Loss detection needs refinement
    double rtt_avg_ns_current = 0.0;
    double rtt_min_ns_current = 1e18;
    double rtt_max_ns_current = 0.0;
    uint64_t rtt_samples_current = 0;

    // Clock::time_point start_time; // Original field
    uint64_t start_time_ns = 0; // Changed field name and type
    
    // Server-side specific (can be ignored by client)
    uint64_t missing_packets = 0;   
    uint64_t total_expected = 0;    
    uint32_t expected_seq = 0;      
    uint32_t last_received_seq = 0; 
    bool seq_initialized = false;   
    uint64_t packets_received = 0;  
    uint64_t last_packets_received = 0;
    uint64_t bytes_received = 0;    
    uint64_t last_bytes_received = 0;  
    uint64_t packets_resent = 0; // Keep counter

    // Add counter for last interval's ACK count
    uint64_t last_acks_sent = 0; // Tracks individual seqs acked
    uint64_t ack_packets_sent = 0; // Tracks number of ACK packets sent
    uint64_t last_ack_packets_sent = 0; // For interval calculation of ACK packets

    // Function to reset only the interval stats
    void reset_interval_stats() {
        sent_current = 0;
        acks_current = 0;
        // lost_current = 0;
        rtt_min_ns_current = 1e18;
        rtt_max_ns_current = 0.0;
        rtt_avg_ns_current = 0.0;
        rtt_samples_current = 0;
    }
};

// Add helper function before run_client
void update_rtt_stats(Stats& stats, uint64_t send_ns, uint64_t now_ns) {
    uint64_t rtt_ns = now_ns - send_ns;
    
    // Update all-time RTT stats
    stats.rtt_samples++;
    stats.rtt_avg_ns = stats.rtt_avg_ns + (rtt_ns - stats.rtt_avg_ns) / stats.rtt_samples;
    stats.rtt_min_ns = std::min(stats.rtt_min_ns, static_cast<double>(rtt_ns));
    stats.rtt_max_ns = std::max(stats.rtt_max_ns, static_cast<double>(rtt_ns));
}

// Add thread-safe stats structure
struct ThreadSafeStats : public Stats {
    std::mutex mtx;             // Mutex for general stats (sent, acks, rtt, etc.)
    std::mutex map_mtx;         // Separate mutex for the in-flight map
    std::map<uint32_t, uint64_t> packets_in_flight; // seq -> send_ns
    
    // Updates both all-time and current interval RTT stats
    void update_rtt(uint64_t send_ns, uint64_t now_ns) {
        std::lock_guard<std::mutex> lock(mtx);
        if (now_ns <= send_ns) return; 
        uint64_t rtt_ns = now_ns - send_ns;
        
        // Update all-time
        rtt_samples++;
        rtt_avg_ns = rtt_avg_ns + (rtt_ns - rtt_avg_ns) / rtt_samples;
        rtt_min_ns = std::min(rtt_min_ns, static_cast<double>(rtt_ns));
        rtt_max_ns = std::max(rtt_max_ns, static_cast<double>(rtt_ns));

        // Update current interval
        rtt_samples_current++;
        rtt_avg_ns_current = rtt_avg_ns_current + (rtt_ns - rtt_avg_ns_current) / rtt_samples_current;
        rtt_min_ns_current = std::min(rtt_min_ns_current, static_cast<double>(rtt_ns));
        rtt_max_ns_current = std::max(rtt_max_ns_current, static_cast<double>(rtt_ns));
    }

    // Add packet to in-flight map
    void add_in_flight(uint32_t seq, uint64_t send_ns) {
        std::lock_guard<std::mutex> lock(map_mtx);
        packets_in_flight[seq] = send_ns;
    }

    // Remove packet from in-flight map, return send_ns if found
    std::optional<uint64_t> remove_in_flight(uint32_t seq) {
        std::lock_guard<std::mutex> lock(map_mtx);
        auto it = packets_in_flight.find(seq);
        if (it != packets_in_flight.end()) {
            uint64_t send_ns = it->second;
            packets_in_flight.erase(it);
            return send_ns;
        }
        return std::nullopt;
    }

    // Get current number of packets in flight
    size_t get_in_flight_count() {
        std::lock_guard<std::mutex> lock(map_mtx);
        return packets_in_flight.size();
    }
    
    // Helper to get a snapshot of sequence numbers currently in flight
    std::vector<uint32_t> get_in_flight_seqs() {
        std::lock_guard<std::mutex> lock(map_mtx);
        std::vector<uint32_t> seqs;
        if (!packets_in_flight.empty()) { 
             seqs.reserve(packets_in_flight.size());
             for (const auto& pair : packets_in_flight) {
                 seqs.push_back(pair.first);
             }
             std::sort(seqs.begin(), seqs.end()); 
        }
        return seqs;
    }

    // Updates both all-time and current interval ACK count
    void record_acks_received(uint32_t count) {
        std::lock_guard<std::mutex> lock(mtx);
        acks += count;
        acks_current += count;
    }
    
    // Updates both all-time and current interval sent count
    void record_packet_sent() {
         std::lock_guard<std::mutex> lock(mtx);
         sent++;
         sent_current++;
    }

    // Safely increment the lost packet counter
    void record_packet_lost(uint32_t count = 1) {
        std::lock_guard<std::mutex> lock(mtx);
        lost += count;
        // Optionally increment lost_current too if interval loss tracking is added later
    }

    // Safely increment the resent packet counter
    void record_packet_resent(uint32_t count = 1) {
        std::lock_guard<std::mutex> lock(mtx);
        packets_resent += count;
    }

    // Gets a copy of the stats AND resets interval stats atomically
    void get_stats_and_reset_interval(Stats& copy) {
        std::lock_guard<std::mutex> lock(mtx);
        // Copy all-time stats
        copy = *this; 
        // Copy current interval stats into the copy object
        copy.sent_current = this->sent_current;
        copy.acks_current = this->acks_current;
        copy.rtt_min_ns_current = this->rtt_min_ns_current;
        copy.rtt_avg_ns_current = this->rtt_avg_ns_current;
        copy.rtt_max_ns_current = this->rtt_max_ns_current;
        copy.rtt_samples_current = this->rtt_samples_current;

        // Reset interval stats in the ThreadSafeStats object
        this->reset_interval_stats();
    }

    // Simple getter needed for initialization or non-resetting peeks
    void get_stats(Stats& copy) {
        std::lock_guard<std::mutex> lock(mtx);
        copy = *this; 
    }

    // Check for and remove timed-out packets from the in-flight map
    // Returns the number of packets evicted.
    size_t evict_timed_out_packets(uint64_t current_time_ns, uint64_t timeout_ns, bool verbose) {
        std::lock_guard<std::mutex> lock(map_mtx);
        size_t evicted_count = 0;
        
        for (auto it = packets_in_flight.begin(); it != packets_in_flight.end(); /* no increment here */ ) {
            uint64_t packet_send_time = it->second;
            if (current_time_ns > packet_send_time && // Basic sanity check
                (current_time_ns - packet_send_time) > timeout_ns) 
            {
                uint32_t timed_out_seq = it->first;
                record_packet_lost(); // Increment lost counter (needs mtx, but we call method)
                if (verbose) {
                    std::cout << "\n*** TIMEOUT DETECTED *** Evicting packet seq=" << timed_out_seq 
                              << " (sent " << (current_time_ns - packet_send_time) / 1000ull << " us ago)\n";
                }
                // Erase returns iterator to the next element, safe during iteration
                it = packets_in_flight.erase(it); 
                evicted_count++;
            } else {
                // Only increment iterator if we didn't erase
                ++it;
            }
        }
        return evicted_count;
    }

    // Update timestamp for a packet already in flight (e.g., on resend)
    bool update_in_flight_timestamp(uint32_t seq, uint64_t new_send_ns) {
        std::lock_guard<std::mutex> lock(map_mtx);
        auto it = packets_in_flight.find(seq);
        if (it != packets_in_flight.end()) {
            it->second = new_send_ns;
            return true;
        }
        return false; // Packet wasn't found (maybe ACKed just before resend?)
    }

    // Find the sequence number of the oldest packet exceeding the timeout
    std::optional<uint32_t> find_oldest_timed_out_packet(uint64_t current_time_ns, uint64_t timeout_ns) {
        std::lock_guard<std::mutex> lock(map_mtx);
        std::optional<uint32_t> oldest_timed_out_seq;
        uint64_t min_send_time_found = UINT64_MAX; // Used to find oldest among timed-out

        if (timeout_ns == 0) return std::nullopt; // Timeout disabled

        for (const auto& pair : packets_in_flight) {
            uint64_t packet_send_time = pair.second;
            if (current_time_ns > packet_send_time && 
                (current_time_ns - packet_send_time) > timeout_ns) 
            { 
                // This packet has timed out. Is it the oldest timed-out one?
                if (packet_send_time < min_send_time_found) { // Check if older than current oldest found
                     // Found an older timed-out packet, potentially the actual oldest by seq indirectly
                     // If map iteration order correlates with insertion (which it does for std::map based on key), 
                     // the first one found *might* be the oldest, but checking send time is safer conceptually.
                     // However, std::map iterates by key order (sequence number). So the *first* match *is* the oldest.
                     // Let's simplify based on map iteration order.
                     oldest_timed_out_seq = pair.first;
                     return oldest_timed_out_seq; // Return immediately upon finding the first (lowest seq)
                     
                     // --- Alternative if iteration order wasn't guaranteed --- 
                     // min_send_time_found = packet_send_time;
                     // oldest_timed_out_seq = pair.first;
                     // --- End Alternative --- 
                }
            }
        }
        // If loop finishes without returning, return the found seq (or nullopt if none found)
        return oldest_timed_out_seq; 
    }

    // Safely increment ACK counters (both individual seqs and packets)
    void record_acks_sent(uint32_t count) {
        std::lock_guard<std::mutex> lock(mtx);
        acks += count;
        // If tracking interval ACKs sent becomes necessary later, add:
        // acks_sent_current += count; 
    }

    // Safely increment the counter for ACK *packets* sent
    void record_ack_packet_sent() {
        std::lock_guard<std::mutex> lock(mtx);
        ack_packets_sent++;
        // If tracking interval ACK packets sent becomes necessary later, add:
        // ack_packets_sent_current++;
    }
};

//---------------------------------------------- Socket helpers
static void bind_interface(int sock, const std::string& ifname) {
    if (ifname.empty()) return;
    unsigned int ifidx = if_nametoindex(ifname.c_str());
    if (!ifidx) { 
        std::cerr << "Error: Invalid network interface '" << ifname << "'\n";
        perror("if_nametoindex"); 
        exit(1);
    }
    if (setsockopt(sock, IPPROTO_IP, IP_BOUND_IF, &ifidx, sizeof(ifidx)) < 0) {
        std::cerr << "Error: Failed to bind to interface '" << ifname << "'\n";
        perror("setsockopt(IP_BOUND_IF)"); 
        exit(1);
    }
    std::cout << "Successfully bound to interface '" << ifname << "'\n";
}

// Calculate IP checksum
static uint16_t ip_checksum(const void* buf, size_t len) {
    const uint16_t* words = static_cast<const uint16_t*>(buf);
    uint32_t sum = 0;
    for (size_t i = 0; i < len/2; i++) {
        sum += ntohs(words[i]);
    }
    if (len & 1) {
        sum += ntohs(static_cast<const uint8_t*>(buf)[len-1]);
    }
    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    return ~sum;
}

// Calculate UDP checksum
static uint16_t udp_checksum(const void* buf, size_t len, const in_addr& src, const in_addr& dst) {
    struct { uint32_t src; uint32_t dst; uint8_t zero; uint8_t proto; uint16_t len; } pseudo;
    pseudo.src = src.s_addr; pseudo.dst = dst.s_addr; pseudo.zero = 0; pseudo.proto = IPPROTO_UDP; pseudo.len = htons(len);
    uint32_t sum = 0;
    const uint16_t* words = reinterpret_cast<const uint16_t*>(&pseudo);
    for (size_t i = 0; i < sizeof(pseudo)/2; i++) { sum += ntohs(words[i]); }
    words = static_cast<const uint16_t*>(buf);
    for (size_t i = 0; i < len/2; i++) { sum += ntohs(words[i]); }
    if (len & 1) { sum += ntohs(static_cast<const uint8_t*>(buf)[len-1]); }
    while (sum >> 16) { sum = (sum & 0xFFFF) + (sum >> 16); }
    return ~sum;
}

// Definition for make_pcap_handle
static pcap_t* make_pcap_handle(const std::string& ifname, const in_addr& src_addr, 
                                bool server, bool distinct_ports, 
                                uint16_t filter_dst_port, uint16_t filter_src_port) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev = ifname;
    if (dev.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) { std::cerr << "Error finding network devices: " << errbuf << "\n"; exit(1); }
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) { if (!(d->flags & PCAP_IF_LOOPBACK)) { dev = d->name; break; } }
        pcap_freealldevs(alldevs);
        if (dev.empty()) { std::cerr << "Error: No suitable network interface found\n"; exit(1); }
        std::cout << "Info: Using network interface: " << dev << "\n";
    }
    pcap_t* handle = pcap_create(dev.c_str(), errbuf);
    if (handle == nullptr) { std::cerr << "Error creating pcap handle on " << dev << ": " << errbuf << "\n"; exit(1); }
    if (pcap_set_immediate_mode(handle, 1) != 0) { std::cerr << "Error setting immediate mode on " << dev << "\n"; pcap_close(handle); exit(1); }
    if (pcap_set_buffer_size(handle, 1024 * 1024) != 0) { std::cerr << "Error setting buffer size on " << dev << "\n"; pcap_close(handle); exit(1); }
    if (pcap_activate(handle) != 0) { std::cerr << "Error activating pcap handle on " << dev << ": " << pcap_geterr(handle) << "\n"; pcap_close(handle); exit(1); }
    char filter_exp[256]; 
    if (distinct_ports) { snprintf(filter_exp, sizeof(filter_exp), "udp dst port %d and src port %d", filter_dst_port, filter_src_port);
    } else { snprintf(filter_exp, sizeof(filter_exp), "udp port %d and not src host %s", filter_dst_port, inet_ntoa(src_addr)); }
    std::cout << "Info: Pcap filter set to: [" << filter_exp << "] on interface " << dev << "\n";
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) { std::cerr << "Error compiling filter [" << filter_exp << "]: " << pcap_geterr(handle) << "\n"; pcap_close(handle); exit(1); }
    if (pcap_setfilter(handle, &fp) == -1) { std::cerr << "Error setting filter: " << pcap_geterr(handle) << "\n"; pcap_freecode(&fp); pcap_close(handle); exit(1); }
        pcap_freecode(&fp);
    return handle;
}

// Definition for make_pcap_send_handle
static pcap_t* make_pcap_send_handle(const std::string& ifname) {
    char errbuf[PCAP_ERRBUF_SIZE];
    std::string dev = ifname;
    if (dev.empty()) {
        pcap_if_t* alldevs;
        if (pcap_findalldevs(&alldevs, errbuf) == -1) { std::cerr << "Error finding network devices: " << errbuf << "\n"; return nullptr; }
        for (pcap_if_t* d = alldevs; d != nullptr; d = d->next) { if (!(d->flags & PCAP_IF_LOOPBACK)) { dev = d->name; break; } }
        pcap_freealldevs(alldevs);
        if (dev.empty()) { std::cerr << "Error: No suitable network interface found for sending\n"; return nullptr; }
        std::cout << "Info: Using network interface for sending: " << dev << "\n";
    }
    pcap_t* handle = pcap_open_live(dev.c_str(), 2048, 0, 1, errbuf);
    if (handle == nullptr) { std::cerr << "Error opening device " << dev << " for sending: " << errbuf << "\n"; return nullptr; }
    std::cout << "Info: Successfully opened pcap handle for sending on " << dev << "\n";
    return handle;
}

//---------------------------------------------- RTT tracker
struct RttTracker {
    std::deque<uint64_t> samples_ns;
    void add(uint64_t v) {
        if (samples_ns.size() == RTT_WINDOW) samples_ns.pop_front();
        samples_ns.push_back(v);
    }
    void compute(double& avg, double& mn, double& mx) {
        if (samples_ns.empty()) return;
        uint64_t sum = std::accumulate(samples_ns.begin(), samples_ns.end(), uint64_t{0});
        avg = static_cast<double>(sum) / samples_ns.size();
        mn  = static_cast<double>(*std::min_element(samples_ns.begin(), samples_ns.end()));
        mx  = static_cast<double>(*std::max_element(samples_ns.begin(), samples_ns.end()));
    }
};

//---------------------------------------------- BPF Socket Helper (may be unused)
static int make_bpf_socket(const std::string& ifname, uint16_t port) {
    char bpfdev[32];
    int bpf_fd = -1;
    
    std::cout << "Opening BPF device...\n";
    // Find an available BPF device
    for (int i = 0; i < 10; i++) {
        snprintf(bpfdev, sizeof(bpfdev), "/dev/bpf%d", i);
        std::cout << "Trying " << bpfdev << "...\n";
        bpf_fd = open(bpfdev, O_RDWR);
        if (bpf_fd >= 0) {
            std::cout << "Successfully opened " << bpfdev << "\n";
            break;
        }
    }
    
    if (bpf_fd < 0) {
        perror("open(/dev/bpf)");
        return -1;
    }
    
    std::cout << "Setting BPF buffer size...\n";
    // Set buffer size first
    int bufsize = 1024 * 1024;
    if (ioctl(bpf_fd, BIOCSBLEN, &bufsize) < 0) {
        perror("ioctl(BIOCSBLEN)");
        close(bpf_fd);
        return -1;
    }
    std::cout << "BPF buffer size set to " << bufsize << " bytes\n";
    
    std::cout << "Binding to interface " << ifname << "...\n";
    // Get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, ifname.c_str(), IFNAMSIZ - 1);
    if (ioctl(bpf_fd, BIOCSETIF, &ifr) < 0) {
        perror("ioctl(BIOCSETIF)");
        close(bpf_fd);
        return -1;
    }
    std::cout << "Successfully bound to interface " << ifname << "\n";
    
    // Set immediate mode
    int immediate = 1;
    if (ioctl(bpf_fd, BIOCIMMEDIATE, &immediate) < 0) {
        perror("ioctl(BIOCIMMEDIATE)");
        close(bpf_fd);
        return -1;
    }
    
    // Set BPF filter to allow all packets
    struct bpf_program filter;
    struct bpf_insn insns[] = {
        BPF_STMT(BPF_RET+BPF_K, 0xFFFFFFFF)  // Accept all packets
    };
    
    filter.bf_len = sizeof(insns) / sizeof(struct bpf_insn);
    filter.bf_insns = insns;
    
    if (ioctl(bpf_fd, BIOCSETF, &filter) < 0) {
        perror("ioctl(BIOCSETF)");
        close(bpf_fd);
        return -1;
    }
    
    std::cout << "BPF socket setup complete\n";
    
    return bpf_fd;
}

// **** Mach Time Helper ****
uint64_t get_time_ns(void) {
    static mach_timebase_info_data_t timebase = {0};
    // Initialize timebase info if not already done
    if (timebase.denom == 0) {
        kern_return_t ret = mach_timebase_info(&timebase);
        if (ret != KERN_SUCCESS) {
            std::cerr << "Fatal Error: mach_timebase_info failed: " << ret << std::endl;
            exit(EXIT_FAILURE); // Can't proceed without timebase
        }
    }
    // Get current time in ticks
    uint64_t ticks = mach_absolute_time();
    // Convert to nanoseconds
    // Perform calculation carefully to avoid overflow
    uint64_t high = (ticks >> 32) * timebase.numer;
    uint64_t low = (ticks & 0xFFFFFFFFULL) * timebase.numer;
    uint64_t high_rem = ((high % timebase.denom) << 32) / timebase.denom;
    uint64_t high_quot = high / timebase.denom;
    uint64_t low_rem = (low % timebase.denom);
    uint64_t low_quot = low / timebase.denom;
    return (high_quot << 32) + low_quot + (high_rem + low_rem) / timebase.denom;
    // Simpler version (potential overflow on intermediate `ticks * numer`):
    // return (ticks * timebase.numer) / timebase.denom;
}

//---------------------------------------------- SERVER
static void run_server(uint16_t port, size_t payload, const std::string& ifname, bool verbose, size_t max_in_flight, bool use_udp, bool distinct_ports) {
    std::cout << "Starting server on main port " << port << " with window size " << max_in_flight << "\n";
    
    // Calculate distinct ports if needed
    uint16_t client_data_src_port = 0; // Port client sends data from (-D mode)
    uint16_t server_ack_src_port = 0;  // Port server sends ACKs from (-D mode)
    uint16_t server_listen_port = port; // Port server listens for data on
    if (!use_udp && distinct_ports) {
        client_data_src_port = port + 1;
        server_ack_src_port = port + 2;
        // Server still listens on the main port for data
        std::cout << "Info: Distinct ports active. Listening for data on " << server_listen_port 
                  << " (expecting src=" << client_data_src_port 
                  << "). Sending ACKs from " << server_ack_src_port << ".\n";
    }

    // --- Setup Network Handles --- 
    pcap_t* recv_handle = make_pcap_handle(ifname, in_addr{}, true, distinct_ports, 
                                       server_listen_port, // Dst port for filter
                                       client_data_src_port); // Src port for filter (0 if not distinct)
    if (!recv_handle) {
        std::cerr << "Error: Failed to create pcap receive handle\n";
            exit(1);
        }

    // Handle/Socket for sending ACKs
    int ack_udp_sock = -1; // For UDP mode
    pcap_t* ack_send_handle = nullptr; // For BPF/pcap mode

    // --- Setup State (Reverted from Atomics) --- 
    ThreadSafeStats stats; 
    stats.start_time_ns = get_time_ns(); 
    uint64_t t_prev_ns = stats.start_time_ns; // For periodic stat printing
    
    // Struct to hold info about pending ACKs
    struct PendingAckInfo {
        uint32_t seq;
        uint64_t send_ns;
        uint16_t client_batch_size;
        uint16_t client_no_in_batch;
    };
    std::deque<PendingAckInfo> pending_acks;

    uint64_t last_ack_time_ns = stats.start_time_ns; 
    uint64_t last_packet_received_time_ns = stats.start_time_ns; 
    uint64_t last_received_data_send_ns = 0;
    
    const uint64_t ACK_INTERVAL_NS = 10 * 1000000ull; // 10ms in nanoseconds (normal interval)
    uint64_t dynamic_min_ack_interval_ns = MIN_ACK_INTERVAL_NS; // Initialize with calculated value
    
    std::vector<uint8_t> recv_buf(HEADER_SIZE + payload);  // Buffer for incoming data
    std::vector<uint8_t> ack_buf; // Buffer for outgoing ACKs
    
    // Calculate max needed size for ACK UDP payload (sequences or padding)
    size_t max_sequences_payload = HEADER_SIZE + max_in_flight * sizeof(uint32_t);
    size_t max_ack_udp_payload_needed = std::max(max_sequences_payload, (size_t)MIN_ACK_SIZE);
    if (MIN_ACK_SIZE == 0) { // If padding disabled, only need space for sequences
        max_ack_udp_payload_needed = max_sequences_payload;
    }

    if (use_udp) { // Size for UDP payload only
          ack_buf.resize(max_ack_udp_payload_needed); 
    } else { // Size for full Ethernet frame
          ack_buf.resize(sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + max_ack_udp_payload_needed);
    }
    
    size_t batch_size = max_in_flight / 2; // Keep batch size logic 
 
    // Variables to store client address info (populated on first packet)
    bool client_info_set = false;
    struct sockaddr_in client_addr_udp; // Used by UDP sender
    in_addr client_ip_addr;             // Used by BPF sender
    uint8_t client_mac_addr[6] = {0};   // Used by BPF sender

    // Sequence history for duplicate detection (remains in main thread)
    std::deque<uint32_t> history;

    // Get server's source MAC/IP (needed for BPF sending)
    uint8_t src_mac[6] = {0};
    struct in_addr src_addr;
    src_addr.s_addr = INADDR_ANY; 
    if (!use_udp) { // Setup needed for BPF
        // ... [Code to get source MAC and IP as before] ...
         struct ifaddrs* ifaddrs_list;
         if (getifaddrs(&ifaddrs_list) != 0) {
             perror("getifaddrs");
             pcap_close(recv_handle);
            exit(1);
        }
         for (struct ifaddrs* ifa = ifaddrs_list; ifa != nullptr; ifa = ifa->ifa_next) {
             if (!ifa->ifa_addr) continue;
             if (strcmp(ifa->ifa_name, ifname.c_str()) == 0) {
                 if (ifa->ifa_addr->sa_family == AF_INET) {
                     src_addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                 } else if (ifa->ifa_addr->sa_family == AF_LINK) {
                     auto* sdl = reinterpret_cast<sockaddr_dl*>(ifa->ifa_addr);
                     if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == 6) { 
                         memcpy(src_mac, LLADDR(sdl), 6);
                     }
                 }
             }
         }
         freeifaddrs(ifaddrs_list);
        // Print source info
        printf("Source MAC for ACKs: %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        std::cout << "Source IP for ACKs: " << inet_ntoa(src_addr) << "\n";
    }

    // Set up socket/handle for sending ACKs
    if (use_udp) {
        ack_udp_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (ack_udp_sock < 0) { perror("socket (ACK)"); pcap_close(recv_handle); exit(1); }
        // Bind UDP ACK socket (optional, allows receiving on same port if needed, but primarily for sending)
        struct sockaddr_in bind_addr; 
        memset(&bind_addr, 0, sizeof(bind_addr));
        bind_addr.sin_family = AF_INET; 
        bind_addr.sin_addr.s_addr = INADDR_ANY; 
        bind_addr.sin_port = htons(port); // Bind to main port, ACKs sent *to* client's ephemeral port
        if (bind(ack_udp_sock, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) { 
            perror("bind (ACK socket)"); pcap_close(recv_handle); close(ack_udp_sock); exit(1); 
        }
    } else {
        ack_send_handle = make_pcap_send_handle(ifname);
        if (ack_send_handle == nullptr) {
            std::cerr << "Error: Failed to create pcap send handle for ACKs\n";
            pcap_close(recv_handle);
            exit(1);
        }
    }

    std::cout << "\nServer ready. Waiting for packets..." << std::endl;
    while (true) { // Main receive loop
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(recv_handle, &header, &packet);
 
        // Handle pcap_next_ex return values
        if (res == -1) { std::cerr << "Error reading packet: " << pcap_geterr(recv_handle) << "\n"; continue; } // Error reading
        if (res == -2) { std::cerr << "EOF from pcap\n"; break; } // End of capture
        // Continue processing even if res == 0 (timeout)

        // --- Process Received Packet (if any) ---
        if (res == 1) { // Packet received
            if (header->caplen < sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr) + HEADER_SIZE) {
                 std::cerr << "Warning: Received runt frame size=" << header->caplen << " bytes, skipping.\n";
                 // Skip to ACK check below
            } else {
                // Parse headers
                const struct ether_header* eth_hdr_recv = (const struct ether_header*)packet;
                const u_char* ip_packet = packet + sizeof(struct ether_header);
                const struct ip* iph_recv = (const struct ip*)ip_packet;
                size_t ip_header_len = iph_recv->ip_hl * 4;
                if (header->caplen < sizeof(struct ether_header) + ip_header_len + sizeof(struct udphdr) + HEADER_SIZE) {
                     std::cerr << "Warning: Received frame size=" << header->caplen << " with IP header size=" << ip_header_len << ", skipping.\n";
                      // Skip to ACK check below
                } else {
                     const struct udphdr* udph_recv = (const struct udphdr*)(ip_packet + ip_header_len);
                     const u_char* payload_data = (const u_char*)(udph_recv + 1);
                     auto* hdr = reinterpret_cast<const Header*>(payload_data);

                    if (hdr->magic == MAGIC) {
                         if (hdr->type == 0 && hdr->payload_len > 0) {  // Process data packets (type 0)
                             uint64_t current_recv_time = get_time_ns();
                             last_packet_received_time_ns = current_recv_time;
                             last_received_data_send_ns = hdr->send_ns;

                             // Store client address info on first valid packet
                             if (!client_info_set) {
                                 client_ip_addr = iph_recv->ip_src;
                                 memcpy(client_mac_addr, eth_hdr_recv->ether_shost, 6);
                                 memset(&client_addr_udp, 0, sizeof(client_addr_udp));
                                 client_addr_udp.sin_family = AF_INET;
                                 client_addr_udp.sin_addr = iph_recv->ip_src;
                                 client_addr_udp.sin_port = udph_recv->uh_sport; 
                                 client_info_set = true;
                                 std::cout << "Info: Stored client address info.\n";
                             }
                             
                             // Update batch size (potential race if client changes it rapidly)
                              if (hdr->batch_size != batch_size && hdr->batch_size > 0) {
                                  batch_size = hdr->batch_size; // Assign uint16_t to size_t is fine
                                  if (verbose) std::cout << "Verbose: Batch size updated to: " << batch_size << "\n";
                              }

                             uint32_t seq = hdr->seq;
                             bool duplicate = std::find(history.begin(), history.end(), seq) != history.end();
                             if (duplicate) {
                                 stats.dup++;
                                 if (verbose) std::cout << "Verbose (Main Thread): Duplicate packet seq=" << seq << "\n";
                             } else {
                                 // Update stats (missing, total, etc.)
                                 stats.packets_received++;
                                 stats.bytes_received += HEADER_SIZE + hdr->payload_len;
                                  if (!stats.seq_initialized) {
                                      stats.expected_seq = seq; 
                                      stats.last_received_seq = seq;
                                      stats.seq_initialized = true;
                                      stats.total_expected = 1; 
                                  } else {
                                      if (seq > stats.expected_seq) {
                                          uint32_t missing_count = seq - stats.expected_seq;
                                          stats.missing_packets += missing_count;
                                          std::cout << "\n*** MISSING SEQ DETECTED *** prev=" << stats.last_received_seq 
                                                    << " lost_range=[ " << stats.expected_seq << " ... " << (seq - 1) 
                                                    << " ] (count=" << missing_count << ") current_rcvd=" << seq << std::endl;
                                      }
                                      stats.total_expected += (seq - stats.expected_seq) + 1;
                                      stats.expected_seq = seq + 1; 
                                      stats.last_received_seq = seq; 
                                  }
                                 // Add to history buffer
                                 history.push_back(seq);
                                 if (history.size() > MAX_WINDOW) history.pop_front(); 

                                 // Add to pending acknowledgments queue
                                 {
                                     pending_acks.push_back({seq, hdr->send_ns, hdr->batch_size, hdr->no_in_batch});
                                 }
                                 if (verbose) std::cout << "Verbose (Main Thread): Added seq=" << seq << " (batch " 
                                                       << hdr->no_in_batch << "/" << hdr->batch_size 
                                                       << ") to pending_acks queue.\n";
                             } // end if (!duplicate)
                         } // end if (type == 0 && payload_len > 0)
                         // Ignore received ACK packets (type 1 or payload_len == 0) and other types
                         else if (verbose && hdr->type != 1) { // Don't log warnings for expected ACK packets
                             std::cout << "Verbose (Main Thread): Ignored packet with type=" << hdr->type 
                                       << " payload=" << hdr->payload_len << " seq=" << hdr->seq << "\n";
                         }
                     } else if (verbose) {
                         std::cout << "Verbose (Main Thread): Received packet with invalid magic: 0x" << std::hex << hdr->magic 
                                   << " (expected 0x" << MAGIC << ")\n" << std::dec;
                     } 
                  }
            } // End of packet parsing block
        } // End if (res == 1)

        // --- Inline ACK Sending Logic (Restored and Optimized) ---
        uint64_t now_ack_check_ns = get_time_ns();
        uint64_t current_last_ack_ns = last_ack_time_ns; // Read non-atomic timestamp
        uint64_t current_last_recv_ns = last_packet_received_time_ns; 

        // Use the dynamically adjusted minimum interval for the check
        bool min_rate_interval_elapsed = now_ack_check_ns - current_last_ack_ns >= dynamic_min_ack_interval_ns;
        bool recently_received_packet = now_ack_check_ns - current_last_recv_ns < MAX_IDLE_TIME_BEFORE_FORCE_ACK_NS;
        bool normal_interval_elapsed = now_ack_check_ns - current_last_ack_ns >= ACK_INTERVAL_NS;

        bool should_send_ack = false;
        size_t ack_count = 0;             // This will store the ACTUAL number of ACKs collected
        uint64_t ack_send_ns = 0;
        std::vector<uint32_t> ack_seqs_to_fill; // Store sequences just before filling buffer
        bool send_empty_ack = false;

        // Decide whether to send an ACK and collect sequences if needed
        if (min_rate_interval_elapsed && recently_received_packet) {
            if (pending_acks.empty()) {
                // Timer triggered, queue empty: Send empty ACK
                should_send_ack = true;
                send_empty_ack = true;
                ack_count = 0;
                ack_send_ns = last_received_data_send_ns; // Use last received packet's send time
            } else {
                // Timer triggered, queue NOT empty: Collect and send normal ACK
                should_send_ack = true;
                send_empty_ack = false;
                size_t target_count = std::min(pending_acks.size(), batch_size); // Decide max to collect
                if (target_count > 0) { // Ensure we don't try to access front() if size is 0 right now
                    ack_send_ns = pending_acks.front().send_ns; // Get timestamp before popping
                    ack_seqs_to_fill.reserve(target_count);
                    while (ack_seqs_to_fill.size() < target_count && !pending_acks.empty()) {
                        ack_seqs_to_fill.push_back(pending_acks.front().seq);
                        pending_acks.pop_front();
                    }
                    ack_count = ack_seqs_to_fill.size(); // Actual collected count
                } else {
                    // Queue became empty between check and collection - don't send normal ACK this time
                    should_send_ack = false; 
                }
            }
        } else {
            // Timer condition not met, check normal batch/interval conditions
            if (!pending_acks.empty()) {
                bool batch_is_full = pending_acks.size() >= batch_size;
                if (batch_is_full || normal_interval_elapsed) {
                    // Batch full OR normal interval elapsed, queue NOT empty: Collect and send normal ACK
                    should_send_ack = true;
                    send_empty_ack = false;
                    size_t target_count = std::min(pending_acks.size(), batch_size); // Decide max to collect
                    if (target_count > 0) { // Ensure we don't try to access front() if size is 0 right now
                        ack_send_ns = pending_acks.front().send_ns; // Get timestamp before popping
                        ack_seqs_to_fill.reserve(target_count);
                        while (ack_seqs_to_fill.size() < target_count && !pending_acks.empty()) {
                            ack_seqs_to_fill.push_back(pending_acks.front().seq);
                            pending_acks.pop_front();
                        }
                        ack_count = ack_seqs_to_fill.size(); // Actual collected count
                        if (ack_count == 0) { // If somehow empty after collecting, abort send
                             should_send_ack = false;
                        }
                    } else {
                         // Queue became empty between check and collection - don't send normal ACK this time
                         should_send_ack = false;
                    }
                }
            }
        }

        // If any condition decided we should send an ACK...
        if (should_send_ack) {
             if (!client_info_set) {
                 // If we collected sequences but can't send, maybe put them back?
                 // For now, let's just log and discard to avoid complexity.
                 if (!ack_seqs_to_fill.empty()) {
                     if (verbose) std::cout << "Verbose: Discarding " << ack_seqs_to_fill.size() 
                                          << " collected ACKs as client info not set.\n";
                 } else {
                    if (verbose) std::cout << "Verbose: ACK trigger skipped (empty or normal), client info not yet set.\n";
                 }
            } else {
                 // Calculate payload size based on ACTUAL collected count (ack_count)
                 size_t ack_payload_size = HEADER_SIZE + ack_count * sizeof(uint32_t);
                 size_t ack_header_offset = 0;
                 size_t total_size = 0;
    
                 // ---- Find the send_ns of the latest "last packet in a batch" being ACKed ----
                 uint64_t batch_rtt_send_ns = 0; // Default to 0
                 uint32_t latest_seq_found = 0;
                 // NOTE: This requires iterating through ack_seqs_to_fill *before* clearing it below
                 //       and relies on the PendingAckInfo struct still holding the data.
                 //       This is inefficient as it iterates again. A better approach would be 
                 //       to find the correct timestamp *while* collecting into ack_seqs_to_fill.
                 //       Implementing the simpler (but less efficient) approach for now.

                 // We need the original PendingAckInfo for each seq in ack_seqs_to_fill.
                 // Let's assume for now we can retrieve it (this part needs refinement/rethink)
                 // THIS LOGIC IS INCOMPLETE / NEEDS REWORK because pending_acks is already popped.
                 // We should ideally process while popping from pending_acks.
                 // *** TEMPORARY PLACEHOLDER LOGIC - MUST BE REFINED ***
                 if (!ack_seqs_to_fill.empty()) {
                    // Placeholder: Use the send_ns from the *last* sequence collected
                    // This is NOT the intended logic but avoids breaking compilation for now.
                    // We need to associate the seq in ack_seqs_to_fill back to its PendingAckInfo.
                    // batch_rtt_send_ns = last_collected_ack_info.send_ns; // Needs actual retrieval
                 }
                 // ---- End Find ----
    
                 // Construct outer headers (if BPF)
                 if (!use_udp) {
                     ack_header_offset = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr);
                     struct ether_header* eth = reinterpret_cast<struct ether_header*>(ack_buf.data());
                     memcpy(eth->ether_shost, src_mac, 6);
                     memcpy(eth->ether_dhost, client_mac_addr, 6);
                     eth->ether_type = htons(ETHERTYPE_IP);
                     struct iphdr* ip = reinterpret_cast<struct iphdr*>(ack_buf.data() + sizeof(struct ether_header));
                     uint8_t* ip_first_byte = ack_buf.data() + sizeof(struct ether_header); *ip_first_byte = 0x45;
                     ip->tos = 0; ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + ack_payload_size);
                     ip->id = htons(0); ip->frag_off = htons(0); ip->ttl = 64; ip->protocol = IPPROTO_UDP;
                     ip->check = 0; ip->saddr = src_addr.s_addr; ip->daddr = client_ip_addr.s_addr;
                     ip->check = ip_checksum(ip, sizeof(struct iphdr));
                     struct udphdr* udp = reinterpret_cast<struct udphdr*>(ack_buf.data() + sizeof(struct ether_header) + sizeof(struct iphdr));
                     if (distinct_ports) {
                         udp->uh_sport = htons(server_ack_src_port);
                         udp->uh_dport = htons(client_data_src_port);
                     } else {
                         udp->uh_sport = htons(port);
                         udp->uh_dport = htons(port);
                     }
                     udp->uh_ulen = htons(sizeof(struct udphdr) + ack_payload_size);
                     udp->uh_sum = 0; 
                     total_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + ack_payload_size;
                 } else {
                     ack_header_offset = 0; // No outer headers for UDP sendto
                     total_size = ack_payload_size; // For UDP, total size is just the payload
                 }
    
                 // Set up our ACK header payload
                 Header* ack_hdr = reinterpret_cast<Header*>(ack_buf.data() + ack_header_offset);
                 ack_hdr->magic = MAGIC;
                 ack_hdr->seq = 0; // Seq 0 indicates ACK packet type
                 ack_hdr->type = 1; // 1 for ACK packet
                 ack_hdr->payload_len = 0;
                 ack_hdr->send_ns = batch_rtt_send_ns; // NEW: use timestamp based on batch completion rule
                 ack_hdr->ack_count = static_cast<uint32_t>(ack_count); // Use actual collected count
                 ack_hdr->batch_size = 0; // Not relevant for ACK
                 ack_hdr->no_in_batch = 0; // Not relevant for ACK
    
                 // Fill sequence numbers if not an empty ACK
                 // We no longer need the separate verbose log vector, use ack_seqs_to_fill directly
                 if (!send_empty_ack) {
                     // Fill directly from ack_seqs_to_fill
                     for (size_t i = 0; i < ack_count; ++i) { // ack_count is already actual_filled_count
                         ack_hdr->ack_seqs[i] = ack_seqs_to_fill[i];
                     }
                     if (verbose) {
                         std::cout << "Verbose: Sending ACK Batch: [ ";
                         for(size_t i=0; i<ack_count; ++i) { std::cout << ack_seqs_to_fill[i] << (i==ack_count-1?"":", "); }
                         std::cout << " ] (" << ack_count << " packets)\n";
                     }
                 } else if (verbose) { 
                      std::cout << "Verbose: Sending empty ACK (timer trigger). send_ns=" << ack_send_ns << std::endl;
                 }
                  
                 // Send the ACK
                 bool sent_ok = false;
                 if (use_udp) {
                     // For UDP, send only the payload part
                     // Recalculate payload size in case ack_count was adjusted due to error
                    size_t final_ack_payload_size = HEADER_SIZE + ack_count * sizeof(uint32_t);
                    if (sendto(ack_udp_sock, ack_buf.data() + ack_header_offset, final_ack_payload_size, 0, (struct sockaddr*)&client_addr_udp, sizeof(client_addr_udp)) >= 0) {
                         sent_ok = true;
                         if (verbose && !send_empty_ack) { // Use collected log_seqs_temp
                              std::cout << "Verbose: Sent UDP ACK Batch: [ ";
                              for(size_t i=0; i<ack_seqs_to_fill.size(); ++i) { std::cout << ack_seqs_to_fill[i] << (i==ack_seqs_to_fill.size()-1?"":", "); }
                              std::cout << " ] (" << ack_count << " packets)\n";
                          } // Empty ACK logged above
                     } else {
                          perror("sendto (ACK)");
                     }
                 } else { // BPF Send
                      struct udphdr* udp = reinterpret_cast<struct udphdr*>(ack_buf.data() + sizeof(struct ether_header) + sizeof(struct iphdr));
                      // Recalculate payload size and total size in case ack_count was adjusted
                      size_t final_ack_payload_size = HEADER_SIZE + ack_count * sizeof(uint32_t);
                      size_t final_total_size = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr) + final_ack_payload_size;
                      // Recalculate IP total length field
                      struct iphdr* ip = reinterpret_cast<struct iphdr*>(ack_buf.data() + sizeof(struct ether_header));
                      ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + final_ack_payload_size);
                      ip->check = 0; // Recalculate IP checksum
                      ip->check = ip_checksum(ip, sizeof(struct iphdr));
                      // Recalculate UDP length field and checksum
                      udp->uh_ulen = htons(sizeof(struct udphdr) + final_ack_payload_size);
                      udp->uh_sum = udp_checksum(udp, sizeof(struct udphdr) + final_ack_payload_size, src_addr, client_ip_addr);

                      if (pcap_sendpacket(ack_send_handle, ack_buf.data(), final_total_size) == 0) {
                         sent_ok = true;
                         if (verbose && !send_empty_ack) { // Use collected log_seqs_temp
                              std::cout << "Verbose: Sent BPF ACK Batch: [ ";
                              for(size_t i=0; i<ack_seqs_to_fill.size(); ++i) { std::cout << ack_seqs_to_fill[i] << (i==ack_seqs_to_fill.size()-1?"":", "); }
                              std::cout << " ] (" << ack_count << " packets)\n";
                          } // Empty ACK logged above
                      } else {
                           std::cerr << "Error sending ACK via pcap: " << pcap_geterr(ack_send_handle) << "\n";
                      }
                  }
    
                 // Update stats and timestamp if send was successful
                 if (sent_ok) {
                     // Use ThreadSafeStats methods (assuming stats is ThreadSafeStats)
                     stats.record_acks_sent(ack_count); // Record actual seqs ACKed
                     stats.record_ack_packet_sent();    // Record one ACK packet sent
                     last_ack_time_ns = get_time_ns(); // Update timestamp after successful send
                 }
            } // end if client_info_set
        } // --- End ACK Sending ---

           // --- Print statistics every second --- 
           uint64_t now_ns_stats = get_time_ns();
           if (now_ns_stats - t_prev_ns >= 1'000'000'000ull) {
               double elapsed_sec = (now_ns_stats - t_prev_ns) / 1e9;
               if (elapsed_sec <= 0) elapsed_sec = 1.0; 

               double missing_percent = 0.0;
               if (stats.total_expected > 0) { 
                   missing_percent = (double)stats.missing_packets / stats.total_expected * 100.0;
               }
               uint64_t packets_this_second = stats.packets_received - stats.last_packets_received;
               double packets_per_sec = packets_this_second / elapsed_sec;
               uint64_t bytes_this_second = stats.bytes_received - stats.last_bytes_received;
               double gbps = (bytes_this_second * 8) / (elapsed_sec * 1e9); 
               stats.last_packets_received = stats.packets_received;
               stats.last_bytes_received = stats.bytes_received;

               // Calculate ACKs sent this interval
               uint64_t acks_this_interval = stats.acks - stats.last_acks_sent;
               double acks_per_sec = acks_this_interval / elapsed_sec;
               stats.last_acks_sent = stats.acks; // Update for next interval

               // Calculate ACK *packets* sent this interval
               uint64_t ack_packets_this_interval = stats.ack_packets_sent - stats.last_ack_packets_sent;
               double ack_packets_per_sec = ack_packets_this_interval / elapsed_sec;
               stats.last_ack_packets_sent = stats.ack_packets_sent; // Update for next interval

               // Use original stats print format
               std::cout << "\r[server] "
                         //<< "Interval: " << std::fixed << std::setprecision(1) << interval_duration_sec << "s"
                         << " | Batch: " << batch_size
                         << " | Size: " << std::fixed << std::setprecision(2) << (batch_size * payload / 1024.0) << " KB"                          
                         << " | RX pps: " << std::fixed << std::setprecision(0) << packets_per_sec // Changed label from TX pps
                         << " | B/W: " << std::fixed << std::setprecision(2) << gbps << " Gb/s";

               // Display INTERVAL RTT stats from the snapshot
               if (stats.rtt_samples_current > 0) { // CORRECTED CONDITION
                   std::cout 
                            //<< " | RTT µs: MIN: " << std::fixed << std::setprecision(1)
                            << stats.rtt_min_ns_current/1000.0 << " | AVG:"
                            << stats.rtt_avg_ns_current/1000.0 << " | MAX:"
                            << stats.rtt_max_ns_current/1000.0;
               } else {
                   // If no RTT data, print ACK rates instead
                   std::cout 
                            //<< " | RTT: no data" 
                             << " | ACKed seq/s: " << std::fixed << std::setprecision(0) << acks_per_sec // Changed label from RX pps
                             << " | ACK TX pps: " << std::fixed << std::setprecision(0) << ack_packets_per_sec; // Added ACK packet rate
               }

               // Always print loss total regardless of RTT data presence
               std::cout << " | Lost(total): " << stats.lost;

               // Display totals and current state
               std::cout << " | Sent(total): " << stats.sent
                         << " | Recvd(total): " << stats.acks // Display total ACKs received
                         << " | InFlight: " << stats.get_in_flight_count() // Get current map size
                         << " | Seq: " << stats.expected_seq << std::flush;
                             
               // --- Dynamic ACK Interval Adjustment --- 
               if (MIN_ACK_RATE_PPS > 0 && elapsed_sec > 0.5) { // Only adjust if enabled and interval is reasonably long
                   const double target_pps = static_cast<double>(MIN_ACK_RATE_PPS);
                   const double error_ratio = (ack_packets_per_sec > 0) ? (target_pps / ack_packets_per_sec) : 2.0; // If 0 pps, try doubling frequency

                   // Simple proportional adjustment factor (adjust strength as needed)
                   double adjustment_factor = 1.0;
                   if (error_ratio > 1.1) { // Measured rate is >10% too low -> decrease interval (increase freq)
                       adjustment_factor = 0.95; // Decrease interval by 5%
                   } else if (error_ratio < 0.9) { // Measured rate is >10% too high -> increase interval (decrease freq)
                       adjustment_factor = 1.05; // Increase interval by 5%
                   }

                   uint64_t new_interval = static_cast<uint64_t>(dynamic_min_ack_interval_ns * adjustment_factor);

                   // Apply limits: prevent interval from becoming too small or too large
                   const uint64_t min_possible_interval = 10000; // 10us (cap at 100k checks/sec)
                   const uint64_t max_possible_interval = 2 * MIN_ACK_INTERVAL_NS; // Don't let it double the original target interval
                   
                   dynamic_min_ack_interval_ns = std::max(min_possible_interval, std::min(new_interval, max_possible_interval));

                   if (verbose && adjustment_factor != 1.0) {
                        std::cout << " | DynACK Adjust: factor=" << std::fixed << std::setprecision(2) << adjustment_factor 
                                  << ", new_interval_us=" << dynamic_min_ack_interval_ns / 1000 << std::flush;
                   }
               } 
               // ----------------------------------------

               // Update for next interval (snapshot is already taken care of by get_stats_and_reset)
               t_prev_ns = now_ns_stats; // Update mach time stats interval
               // last_stats_snapshot = current_stats_snapshot; // No longer needed to store snapshot manually
           } // --- End Stats Printing ---
    } // --- End while(true) --- 
    
    // --- Cleanup --- 
    // No thread to join
   
    std::cout << std::endl << "Server shutting down." << std::endl;
    pcap_close(recv_handle);
    if (use_udp) {
        if (ack_udp_sock >= 0) close(ack_udp_sock);
    } else {
        if (ack_send_handle) pcap_close(ack_send_handle);
    }
}

//---------------------------------------------- CLIENT
struct InFlight { uint64_t send_ns; uint8_t retries; };

// Add receiver thread function
static void receiver_thread_func(pcap_t* handle, int recv_sock, bool verbose, bool& running, ThreadSafeStats& stats, bool continuous_send, bool use_udp) {
    
    // --- Attempt to set ACK receiver thread priority --- 
    pthread_t recv_thread = pthread_self();
    int policy = SCHED_OTHER;
    struct sched_param param;
    int max_priority = sched_get_priority_max(policy);
    if (max_priority == -1) {
        perror("sched_get_priority_max (receiver thread)");
        std::cerr << "Warning (Receiver Thread): Could not get max priority for SCHED_OTHER." << std::endl;
    } else {
        param.sched_priority = max_priority;
        std::cout << "Attempting to set receiver thread priority to " << max_priority 
                  << " (policy SCHED_OTHER)..." << std::endl;
        if (pthread_setschedparam(recv_thread, policy, &param) != 0) {
            perror("pthread_setschedparam (receiver thread)");
            std::cerr << "Warning (Receiver Thread): Failed to set thread priority. May require root privileges (sudo)." << std::endl;
        } else {
            std::cout << "Successfully set receiver thread priority." << std::endl;
        }
    }
    // -------------------------------------------

    std::vector<uint8_t> recv_buf(HEADER_SIZE + MAX_IN_FLIGHT * sizeof(uint32_t));

    while (running) {
        const Header* ack = nullptr;
        bool packet_received = false;

        if (use_udp) {
            // Try to receive from UDP socket
            struct sockaddr_in src_addr;
            socklen_t addr_len = sizeof(src_addr);
            ssize_t recv_len = recvfrom(recv_sock, recv_buf.data(), recv_buf.size(), 
                                      MSG_DONTWAIT, (struct sockaddr*)&src_addr, &addr_len);
            
            if (recv_len >= static_cast<ssize_t>(HEADER_SIZE)) {
                auto* potential_ack = reinterpret_cast<const Header*>(recv_buf.data());
                // Check magic and type field (1 == ACK)
                if (potential_ack->magic == MAGIC && potential_ack->type == 1) { 
                    ack = potential_ack;
                    packet_received = true;
                }
            } else if (recv_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                perror("recvfrom");
            }
        } else {
            // Use PCAP for receiving
            struct pcap_pkthdr* pcap_hdr;
            const u_char* packet_data;
            int res = pcap_next_ex(handle, &pcap_hdr, &packet_data);
            
            if (res == 1) {  // Packet received
                const u_char* ip_packet = packet_data + sizeof(struct ether_header);
                const struct ip* iph = (const struct ip*)ip_packet;
                size_t ip_hdr_len = iph->ip_hl * 4;
                const struct udphdr* udph = (const struct udphdr*)(ip_packet + ip_hdr_len);
                const u_char* payload_data = (const u_char*)(udph + 1);
                size_t expected_min_len = sizeof(struct ether_header) + ip_hdr_len + sizeof(struct udphdr) + HEADER_SIZE;

                if (pcap_hdr->caplen >= expected_min_len) {
                    auto* potential_ack = reinterpret_cast<const Header*>(payload_data);
                    // Check magic and type field (1 == ACK)
                    if (potential_ack->magic == MAGIC && potential_ack->type == 1) {
                        ack = potential_ack;
                        packet_received = true;
                    }
                } else if (verbose) {
                     std::cerr << "Warning: Received runt PCAP packet of size " << pcap_hdr->caplen << " bytes\n";
                }
            } else if (res == -1) {
                std::cerr << "Error reading packet: " << pcap_geterr(handle) << "\n";
            }
        }

        // Process the ACK if received
        if (packet_received && ack) {
            uint32_t ack_count = ack->ack_count;
            stats.record_acks_received(ack_count); // Update ACK counters
            // uint64_t now_ns = std::chrono::duration_cast<ns>(Clock::now().time_since_epoch()).count(); // Use mach time
            uint64_t now_ns = get_time_ns();

            // --- New RTT Calculation based on ACK header timestamp ---
            if (ack->send_ns > 0) {
                // Calculate RTT using the timestamp provided in the ACK header
                stats.update_rtt(ack->send_ns, now_ns); 
            }
            // -------------------------------------------------------

            if (verbose) {
                // Log in-flight packets before processing ACK
                std::vector<uint32_t> in_flight_before = stats.get_in_flight_seqs();
                std::cout << "Verbose ACK Processing: In flight before ACK: [ ";
                for(size_t i = 0; i < in_flight_before.size(); ++i) {
                    std::cout << in_flight_before[i] << (i == in_flight_before.size() - 1 ? "" : ", ");
                }
                std::cout << "] (" << in_flight_before.size() << " packets)\n";

                // Log sequence numbers in the received ACK
                std::cout << "Verbose ACK Processing: Received ACK contains: [ ";
                for(uint32_t i = 0; i < ack_count; ++i) {
                    std::cout << ack->ack_seqs[i] << (i == ack_count - 1 ? "" : ", ");
                }
                std::cout << "] (" << ack_count << " packets)\n";
            }

            uint32_t processed_count = 0;
            // Loop to remove ACKed sequences from the in-flight map
            for (uint32_t i = 0; i < ack_count; ++i) {
                uint32_t current_seq = ack->ack_seqs[i];
                std::optional<uint64_t> send_ns_opt = stats.remove_in_flight(current_seq);
                
                // Original per-packet RTT calculation removed from here:
                // if (send_ns_opt.has_value()) {
                //     stats.update_rtt(send_ns_opt.value(), now_ns); 
                //     processed_count++;
                // } else if (verbose) { ... }

                if (send_ns_opt.has_value()) {
                    processed_count++; // Still count how many were successfully removed
                } else if (verbose) {
                    // Packet already ACKed (duplicate ACK?) or never sent
                    std::cout << "Warning: Received ACK for seq=" << current_seq << " which was not in flight." << std::endl;
                }
            }

            if (verbose) {
                std::cout << "Processed ACK packet: ack_count=" << ack_count 
                          << ", valid_rtt_updates=" << processed_count << std::endl;
            }
        }
        
        // Small sleep to prevent busy waiting if no packet was processed
        if (!packet_received) {
            //std::this_thread::sleep_for(std::chrono::microseconds(1)); 
        }
    }
}

// Forward declaration (if not already present, good practice)
static void run_client(const std::string& dst_ip, uint16_t port, size_t payload, const std::string& ifname,
                       uint32_t rate_pps, uint32_t timeout_us, bool verbose, uint32_t duration_s, 
                       size_t max_in_flight, size_t batch_size, bool use_udp, 
                       bool no_ack, bool continuous_send, bool skip_udp_sockets, bool distinct_ports); // Added skip_udp_sockets and distinct_ports

// Definition of run_client
static void run_client(const std::string& dst_ip, uint16_t port, size_t payload, const std::string& ifname,
                       uint32_t rate_pps, uint32_t timeout_us, bool verbose, uint32_t duration_s, 
                       size_t max_in_flight, size_t batch_size, bool use_udp, 
                       bool no_ack, 
                       bool continuous_send,
                       bool skip_udp_sockets, bool distinct_ports) { // Added skip_udp_sockets and distinct_ports parameter
    
    std::cout << "Starting client to " << dst_ip << ":" << port << " (main port)\n";
    std::cout << "Max In Flight: " << max_in_flight << "\n"
              << "Batch size: " << batch_size << "\n"
              << "Using " << (use_udp ? "normal UDP" : "BPF") << " for sending\n"
              << "Mode: ";
    if (no_ack) {
        std::cout << "No ACK (no waiting, no processing)\n";
    } else if (continuous_send) {
        std::cout << "Continuous send (no waiting, with RTT stats)\n";
    } else {
        std::cout << "Normal\n";
    }
    
    // --- Attempt to set thread priority --- 
    pthread_t main_thread = pthread_self();
    int policy = SCHED_OTHER; // Standard policy on macOS
    struct sched_param param;
    int max_priority = sched_get_priority_max(policy);
    if (max_priority == -1) {
        perror("sched_get_priority_max");
        std::cerr << "Warning: Could not get max priority for SCHED_OTHER." << std::endl;
    } else {
        param.sched_priority = max_priority;
        std::cout << "Attempting to set main thread priority to " << max_priority 
                  << " (policy SCHED_OTHER)..." << std::endl;
        if (pthread_setschedparam(main_thread, policy, &param) != 0) {
            // EPERM typically means insufficient privileges (need sudo?)
            // EINVAL means invalid policy/priority (less likely here)
            perror("pthread_setschedparam");
            std::cerr << "Warning: Failed to set thread priority. May require root privileges (sudo)." << std::endl;
        } else {
            std::cout << "Successfully set thread priority." << std::endl;
        }
    }
    // -------------------------------------
    
    // Get source IP address
    struct in_addr src_addr;
    src_addr.s_addr = INADDR_ANY;
    if (!ifname.empty()) {
        struct ifaddrs* ifaddr;
        if (getifaddrs(&ifaddr) == 0) {
            for (struct ifaddrs* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
                if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && 
                    strcmp(ifa->ifa_name, ifname.c_str()) == 0) {
                    src_addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr)->sin_addr;
                    break;
                }
            }
            freeifaddrs(ifaddr);
        }
    }
    std::cout << "Source IP: " << inet_ntoa(src_addr) << "\n";
    
    // Calculate distinct ports if needed
    uint16_t client_src_port = port; // Default: use main port
    uint16_t server_ack_src_port = port; // Default: expect ACKs from main port
    if (!use_udp && distinct_ports) {
        client_src_port = port + 1;
        server_ack_src_port = port + 2;
        std::cout << "Info: Distinct ports active. Sending from " << client_src_port 
                  << " to " << port << ". Expecting ACKs from " << server_ack_src_port 
                  << " on port " << client_src_port << ".\n";
    }

    // Setup handles/sockets
    pcap_t* send_handle = nullptr; // For BPF send
    pcap_t* recv_handle = nullptr; // For BPF receive
    int recv_sock = -1;           // For UDP receive

    // Set up UDP socket for receiving ACKs if needed (and not skipped)
    if (!no_ack && !skip_udp_sockets) {
        recv_sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (recv_sock < 0) { /* error */ exit(1); }
        std::cout << "Info: Created UDP socket for receiving ACKs (fd=" << recv_sock << ")." << std::endl;
        // ... [bind to interface] ...
        
        // Bind to the correct port
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        uint16_t udp_bind_port = (!use_udp && distinct_ports) ? client_src_port : port;
        std::cout << "Info: Binding UDP receive socket to port: " << udp_bind_port << std::endl;
        addr.sin_port = htons(udp_bind_port);
        if (bind(recv_sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) { /* error */ exit(1); }
    }
    // ... [Skip message] ...

    // Setup pcap handles if BPF mode is used
    if (!use_udp) {
        send_handle = make_pcap_send_handle(ifname); 
        if (!send_handle) { /* error exit */ exit(1); }

        if (!no_ack) {
            // Client listens on its source port for ACKs from server's source port
            recv_handle = make_pcap_handle(ifname, src_addr, false, distinct_ports, 
                                       client_src_port,     // Dst port for filter (client's src)
                                       server_ack_src_port); // Src port for filter (server's src)
            if (!recv_handle) { /* error exit */ exit(1); }
            std::cout << "PCAP receive handle created successfully\n";
        }
    }
    // ... [rest of setup: dst addr, MAC addr, BPF send handle/socket] ...
    
    // Set up destination address
    struct in_addr dst_addr;
    if (inet_pton(AF_INET, dst_ip.c_str(), &dst_addr) <= 0) {
        std::cerr << "Error: Invalid destination IP address '" << dst_ip << "'\n";
        if (!no_ack) pcap_close(send_handle);
        exit(1);
    }
    std::cout << "Destination IP: " << inet_ntoa(dst_addr) << "\n";

    // Get source MAC address for BPF
    uint8_t src_mac[6] = {0};
    uint8_t dst_mac[6] = {0};
    if (!use_udp) {
        struct ifaddrs* ifaddrs;
        if (getifaddrs(&ifaddrs) != 0) {
            perror("getifaddrs");
            exit(1);
        }
        
        // Find interface for MAC address
        for (struct ifaddrs* ifa = ifaddrs; ifa != nullptr; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK &&
                strcmp(ifa->ifa_name, ifname.c_str()) == 0) {
                auto* sdl = reinterpret_cast<sockaddr_dl*>(ifa->ifa_addr);
                if (sdl->sdl_alen == 6) {  // Standard MAC address length
                    memcpy(src_mac, LLADDR(sdl), 6);
                }
            }
        }
        freeifaddrs(ifaddrs);
        
        // Print source MAC address
        printf("Source MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
               src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
        
        // Get destination MAC address using ARP (simplified, just using broadcast for example)
        // In a real implementation, you should perform ARP resolution here
        memset(dst_mac, 0xFF, 6);  // Use broadcast for this example
        printf("Destination MAC: %02x:%02x:%02x:%02x:%02x:%02x (broadcast)\n",
               dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    }

    // Set up sending socket/handle based on mode
    int send_fd = -1; // Only used for UDP mode
    // send_handle is already declared and initialized for BPF above

    if (use_udp) {
        // Use normal UDP socket
        send_fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (send_fd < 0) {
            perror("socket");
            if (!no_ack) {
                close(recv_sock);
                pcap_close(send_handle);
            }
            exit(1);
        }
        
        // Bind to interface if specified
        if (!ifname.empty()) {
            unsigned int ifidx = if_nametoindex(ifname.c_str());
            if (!ifidx) {
                perror("if_nametoindex");
                close(send_fd);
                if (!no_ack) {
                    close(recv_sock);
                    pcap_close(send_handle);
                }
                exit(1);
            }
            if (setsockopt(send_fd, IPPROTO_IP, IP_BOUND_IF, &ifidx, sizeof(ifidx)) < 0) {
                perror("setsockopt(IP_BOUND_IF)");
                close(send_fd);
                if (!no_ack) {
                    close(recv_sock);
                    pcap_close(send_handle);
                }
                exit(1);
            }
        }
        
        // Set up destination address
        struct sockaddr_in dest_addr;
        memset(&dest_addr, 0, sizeof(dest_addr));
        dest_addr.sin_family = AF_INET;
        dest_addr.sin_addr = dst_addr;
        dest_addr.sin_port = htons(port);
        
        if (connect(send_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
            perror("connect");
            close(send_fd);
            if (!no_ack) {
                close(recv_sock);
                pcap_close(send_handle);
            }
            exit(1);
        }
    } else {
        // BPF Mode: send_handle is already created via make_pcap_send_handle
        // Remove the incorrect creation of a separate BPF socket descriptor:
        // send_fd = make_bpf_socket(ifname, port); // <--- REMOVED
        // if (send_fd < 0) { ... } // <--- REMOVED
        if (!send_handle) { // Double check send_handle was created successfully earlier
             std::cerr << "Error: pcap send handle is null in BPF mode.\n";
             // Cleanup other handles/sockets
              if (recv_sock >= 0) close(recv_sock);
              if (recv_handle) pcap_close(recv_handle);
             exit(1);
        }
    }

    // Allocate buffer for packet
    std::vector<uint8_t> buf;
    std::vector<uint8_t> recv_buf(HEADER_SIZE + max_in_flight * sizeof(uint32_t));  // Buffer for receiving ACKs
    if (use_udp) {
        buf.resize(HEADER_SIZE + payload);  // Just payload for UDP
    } else {
        buf.resize(sizeof(ether_header) + sizeof(iphdr) + sizeof(udphdr) + HEADER_SIZE + payload);  // Full packet for BPF
    }
    
    uint32_t seq = 0;
    uint32_t last_acked_seq = 0;  // Track last acknowledged sequence
    ns interval(1'000'000'000ull / rate_pps);  // Nanoseconds between packets
    auto next_send = Clock::now();
    auto start = next_send;

    // Convert Stats to ThreadSafeStats
    ThreadSafeStats stats;
    stats.start_time_ns = get_time_ns(); // Use mach time for start
    auto last_stat_time = stats.start_time_ns; // Use mach time for stats interval
    Stats last_stats_snapshot;
    stats.get_stats(last_stats_snapshot);
    uint64_t interval_evicted_count = 0; // Accumulator for evicted packets per interval

    // Start receiver thread if needed
    bool running = true;
    std::thread receiver;
    if (!no_ack) {
        // Receiver thread needs *either* recv_handle (if !use_udp) *or* recv_sock (if use_udp && !skip_udp_sockets)
        // The thread function itself checks use_udp to decide which handle/socket to use.
        printf("Starting ACK thread\n");
        receiver = std::thread(receiver_thread_func, recv_handle, recv_sock, verbose, std::ref(running), std::ref(stats), continuous_send, use_udp);
    }

    // Rate control using mach time
    uint64_t interval_ns = (rate_pps > 0) ? (1'000'000'000ull / rate_pps) : 0;
    uint64_t next_send_ns = stats.start_time_ns; // Start sending immediately
    const uint64_t start_ns = stats.start_time_ns;
    const uint64_t duration_ns = (duration_s > 0) ? (static_cast<uint64_t>(duration_s) * 1'000'000'000ull) : 0;
    const uint64_t eviction_timeout_ns = static_cast<uint64_t>(timeout_us) * 1000ull; // Convert -t value to ns
    uint16_t current_batch_no = 0; // Counter for no_in_batch field

    std::cout << "Starting packet transmission...\n";
    std::cout << "Press Ctrl+C to stop\n\n";
    
    try {
        // Use mach time for duration check
        while (duration_s == 0 || (get_time_ns() - start_ns) < duration_ns) {
            uint64_t current_time_ns = get_time_ns();
            
            // Check for and evict timed-out packets (only if ACKs are expected)
            // continuous_send ignores ACKS, no need to evict
            if (!no_ack && !continuous_send ) { 
                // Use the timeout derived from the -t flag (converted to ns)
                size_t evicted = stats.evict_timed_out_packets(current_time_ns, eviction_timeout_ns, verbose);
                if (evicted > 0) {
                    interval_evicted_count += evicted; // Accumulate count
                    // Removed the verbose print from here:
                    // std::cout << "Verbose: Evicted " << evicted << " timed-out packets.\n"; 
                }
            }
            
            // Send packets at the specified rate
            bool can_send = no_ack || continuous_send || (stats.get_in_flight_count() < max_in_flight);
            if (can_send && current_time_ns >= next_send_ns) {
                uint64_t send_timestamp_ns = current_time_ns; // Use current mach time as send time
                uint32_t current_seq = seq;
                
                // Add to map BEFORE sending
                if (!no_ack) { // Only track if we expect ACKs
                    stats.add_in_flight(current_seq, send_timestamp_ns); 
                }

                if (use_udp) {
                    // Construct our header for UDP
                    auto* hdr = reinterpret_cast<Header*>(buf.data());
                    hdr->magic = MAGIC;
                    hdr->type = 0; // 0 for data packet
                    hdr->seq = current_seq; // Use captured seq
                    if (no_ack && current_seq > 1000) { seq = 0; } // Reset main seq counter if needed
                    hdr->payload_len = static_cast<uint32_t>(payload);
                    hdr->send_ns = send_timestamp_ns;
                    hdr->batch_size = static_cast<uint16_t>(batch_size); // Cast size_t to uint16_t
                    hdr->no_in_batch = current_batch_no; // Set sequence within batch
                    
                    // Send using UDP socket
                    ssize_t sent = send(send_fd, buf.data(), buf.size(), 0);
                    if (sent > 0) {
                        stats.record_packet_sent();
                        if (verbose) {
                            // Log window size based on map count (reflects state *after* adding)
                            std::cout << "Sent UDP packet " << hdr->seq << " (" << sent << " bytes)"
                                      << " window=" << stats.get_in_flight_count() << "/" << max_in_flight << "\n";
                        }
                        seq++;  // Increment main sequence counter *after* successful send
                        // Increment and wrap batch sequence number
                        if (batch_size > 0) { // Avoid modulo by zero if batch_size is somehow 0
                            current_batch_no = (current_batch_no + 1) % static_cast<uint16_t>(batch_size);
                        }
                        // Use mach time variables for scheduling
                        next_send_ns += interval_ns;
                        if (current_time_ns > next_send_ns + interval_ns * 100) { 
                             next_send_ns = current_time_ns + interval_ns; 
                        }
                    } else {
                        // Handle send error - IMPORTANT: remove from map if send failed!
                         if (!no_ack) {
                             stats.remove_in_flight(current_seq); 
                         }
                        if (errno == ECONNREFUSED) {
                            // Connection refused - try to reconnect
                            if (verbose) {
                                std::cout << "Connection refused, attempting to reconnect...\n";
                            }
                            
                            // Reconnect the existing socket
                            struct sockaddr_in dest_addr;
                            memset(&dest_addr, 0, sizeof(dest_addr));
                            dest_addr.sin_family = AF_INET;
                            dest_addr.sin_addr = dst_addr;
                            dest_addr.sin_port = htons(port);
                            
                            if (connect(send_fd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
                                perror("connect");
                                std::cout << "Error reconnecting socket, errno=" << errno << "\n";
                            } else {
                                // Retry sending the packet
                                sent = send(send_fd, buf.data(), buf.size(), 0);
                                if (sent > 0) {
                                    stats.record_packet_sent();
                                    seq++;  // Only increment on successful send
                                    if (verbose) {
                                        std::cout << "Retry successful - sent UDP packet " << hdr->seq << " (" << sent << " bytes)\n";
                                    }
                                    next_send_ns += interval_ns;
                                    if (current_time_ns > next_send_ns + interval_ns * 100) { 
                                         next_send_ns = current_time_ns + interval_ns; 
                                    }
                                } else {
                                    perror("send (retry)");
                                    std::cout << "Error sending UDP packet " << hdr->seq << " on retry, errno=" << errno << "\n";
                                }
                            }
                        } else {
                            perror("send");
                            std::cout << "Error sending UDP packet " << hdr->seq << ", errno=" << errno << "\n";
                        }
                    }
                } else {
                    // BPF packet construction and sending
                    struct ether_header* eth = reinterpret_cast<struct ether_header*>(buf.data());
                    memcpy(eth->ether_shost, src_mac, 6);
                    memcpy(eth->ether_dhost, dst_mac, 6);
                    eth->ether_type = htons(ETHERTYPE_IP);
                    
                    struct iphdr* ip = reinterpret_cast<struct iphdr*>(buf.data() + sizeof(struct ether_header));
                    uint8_t* ip_first_byte = buf.data() + sizeof(struct ether_header);
                    *ip_first_byte = 0x45;
                    ip->tos = 0;
                    ip->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + HEADER_SIZE + payload);
                    ip->id = htons(0); 
                    ip->frag_off = htons(0);
                    ip->ttl = 64;
                    ip->protocol = IPPROTO_UDP;
                    ip->check = 0; 
                    ip->saddr = src_addr.s_addr;
                    ip->daddr = dst_addr.s_addr;
                    ip->check = ip_checksum(ip, sizeof(struct iphdr));
                    
                    struct udphdr* udp = reinterpret_cast<struct udphdr*>(buf.data() + sizeof(struct ether_header) + sizeof(struct iphdr));
                    // Set ports based on distinct_ports flag
                    if (distinct_ports) {
                        udp->uh_sport = htons(client_src_port); // Use port+1 for source
                        udp->uh_dport = htons(port);            // Use main port for destination
                    } else {
                        udp->uh_sport = htons(port); // Use main port for both
                        udp->uh_dport = htons(port); 
                    }
                    udp->uh_ulen = htons(sizeof(struct udphdr) + HEADER_SIZE + payload);
                    udp->uh_sum = 0; 
                    
                    auto* hdr = reinterpret_cast<Header*>(buf.data() + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr));
                    hdr->magic = MAGIC;
                    hdr->type = 0; // 0 for data packet
                    hdr->seq = current_seq; // Use captured seq
                    if (no_ack && current_seq > 1000) { seq = 0; } // Reset main seq counter if needed
                    hdr->payload_len = static_cast<uint32_t>(payload);
                    hdr->send_ns = send_timestamp_ns;
                    hdr->batch_size = static_cast<uint16_t>(batch_size); // Cast size_t to uint16_t
                    hdr->no_in_batch = current_batch_no; // Set sequence within batch

                    udp->uh_sum = udp_checksum(udp, sizeof(struct udphdr) + HEADER_SIZE + payload, src_addr, dst_addr);
                    
                    // Send packet via BPF using pcap_sendpacket
                    int pcap_ret = pcap_sendpacket(send_handle, buf.data(), buf.size()); // buf.size() includes all headers
                    
                    if (pcap_ret == 0) { // pcap_sendpacket returns 0 on success
                        stats.record_packet_sent();
                        if (verbose) {
                             // Log window size based on map count (reflects state *after* adding)
                            // Use buf.size() as the total bytes sent for the log message
                            std::cout << "Sent BPF packet " << hdr->seq << " (" << buf.size() << " bytes total)"
                                      << " window=" << stats.get_in_flight_count() << "/" << max_in_flight << "\n";
                        }
                        seq++;  // Increment main sequence counter *after* successful send
                        // Increment and wrap batch sequence number
                        if (batch_size > 0) { // Avoid modulo by zero if batch_size is somehow 0
                            current_batch_no = (current_batch_no + 1) % static_cast<uint16_t>(batch_size);
                        }
                        // Use mach time variables for scheduling
                        next_send_ns += interval_ns;
                        if (current_time_ns > next_send_ns + interval_ns * 100) { 
                             next_send_ns = current_time_ns + interval_ns; 
                        }
                    } else {
                        // Handle pcap_sendpacket error
                        if (!no_ack) {
                            stats.remove_in_flight(current_seq); 
                        }
                        std::cerr << "\nError sending BPF packet seq=" << current_seq 
                                  << " via pcap: " << pcap_geterr(send_handle) << std::endl;
                        // Consider adding a small sleep or break here if errors persist?
                    }
                }
            }

            // Print statistics every second
            if (current_time_ns - last_stat_time >= 1000000000ull) { // Use uint64_t ns comparison
                Stats current_stats_snapshot;
                // Atomically get stats snapshot AND reset interval counters for the next period
                stats.get_stats_and_reset_interval(current_stats_snapshot);
                
                double interval_duration_sec = (double)(current_time_ns - last_stat_time) / 1e9;
                if (interval_duration_sec <= 0) interval_duration_sec = 1.0; // Avoid division by zero

                // Calculate interval stats using the snapshot's _current values
                uint64_t interval_sent = current_stats_snapshot.sent_current;
                uint64_t interval_acks = current_stats_snapshot.acks_current;
                // uint64_t interval_lost = current_stats_snapshot.lost_current; // If loss is tracked per interval
                uint64_t interval_payload_bytes = interval_sent * payload;
                // Include L3/L4 headers (IP=20, UDP=8) for a more network-centric B/W measure
                const size_t BYTES_PER_PACKET = HEADER_SIZE + payload + 28; 
                double interval_total_bytes = interval_sent * BYTES_PER_PACKET;
                // double interval_mbps = (interval_total_bytes * 8) / (interval_duration_sec * 1e6); // Mbps - no longer needed
                double interval_pps_sent = interval_sent / interval_duration_sec;
                double interval_pps_acked = interval_acks / interval_duration_sec;
                // Calculate Gbps using total bytes (including L3/L4 headers)
                double interval_gbps = (interval_total_bytes * 8) / (interval_duration_sec * 1e9); 
                double interval_evicted_pps = interval_evicted_count / interval_duration_sec;

                std::cout << "\r[client] "
                          //<< "Interval: " << std::fixed << std::setprecision(1) << interval_duration_sec << "s"
                          << " | Batch: " << batch_size
                          << " | Size: " << std::fixed << std::setprecision(2) << (batch_size * payload / 1024.0) << " KB"                          
                          << " | TX pps: " << std::fixed << std::setprecision(0) << interval_pps_sent
                          << " | B/W: " << std::fixed << std::setprecision(2) << interval_gbps << " Gb/s";

                // Display INTERVAL RTT stats from the snapshot
                if (current_stats_snapshot.rtt_samples_current > 0) { // CORRECTED CONDITION
                    std::cout << " | RTT µs: MIN: " << std::fixed << std::setprecision(1)
                             << current_stats_snapshot.rtt_min_ns_current/1000.0 << " | AVG:"
                             << current_stats_snapshot.rtt_avg_ns_current/1000.0 << " | MAX:"
                             << current_stats_snapshot.rtt_max_ns_current/1000.0;
                } else if (!current_stats_snapshot.rtt_samples_current) {
                    std::cout << " | RTT: no data"; // Show if no samples collected in the interval
                }

                if (!current_stats_snapshot.rtt_samples_current) {
                    std::cout << " | RX pps: " << std::fixed << std::setprecision(0) << interval_pps_acked;
                    // Update loss reporting if/when implemented properly using totals or interval loss
                    std::cout << " | Lost(total): " << current_stats_snapshot.lost; 
                }

                // Display totals and current state
                std::cout << " | Sent(total): " << current_stats_snapshot.sent
                          << " | Recvd(total): " << current_stats_snapshot.acks // Display total ACKs received
                          << " | InFlight: " << stats.get_in_flight_count() // Get current map size
                          << " | Seq: " << current_stats_snapshot.expected_seq; // Use snapshot seq
                
                // Always print Evicted/s for debugging (even if zero)
                 std::cout << " | Evicted/s: " << std::fixed << std::setprecision(0) << interval_evicted_pps;
                
                std::cout << std::flush;
                                 
                 // Update for next interval (snapshot is already taken care of by get_stats_and_reset)
                 last_stat_time = current_time_ns;
                 interval_evicted_count = 0; // Reset accumulator for next interval
            }
            
            
            // Don't busy-wait - sleep for a short time if we're ahead of schedule
            //auto sleep_time = next_send - Clock::now();
            //if (sleep_time > ns(0)) {
            //    //std::this_thread::sleep_for(std::min(sleep_time, interval));
            //}
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    
    // Clean up
    running = false;
    if (!no_ack && receiver.joinable()) {
        receiver.join();
    }
    
    // Close the correct sending mechanism
    if (use_udp) {
        if (send_fd >= 0) close(send_fd); // Only close send_fd if UDP was used
    } else {
        if (send_handle) pcap_close(send_handle);
    }
    
    // Close the correct receiving mechanism(s)
    if (recv_sock >= 0) { // Only close if it was created
        close(recv_sock);
    }
    if (recv_handle) { // Only close if it was created
         pcap_close(recv_handle);
    }
    
    std::cout << "\nTransmission complete\n";
}

//---------------------------------------------- MAIN
static void help() {
    std::cerr
        << "Thunderbolt UDP tester\n"
        << "Usage: udp_tbolt_tester [-s] [-c ip] [-p port] [-i if] [-r pps] "
           "[-z bytes] [-t timeout_us] [-d sec] [-m max_in_flight] [-b batch_size] [-v] [-u] [-n|-n2] [-x] [-D]\n"
        << "Options:\n"
        << "  -s               server (responder) mode (default = client)\n"
        << "  -c <addr>        destination IPv4 address (client only)\n"
        << "  -p <port>        UDP port (default 8888)\n"
        << "  -i <ifname>      bind to network interface (macOS ≥10.7)\n"
        << "  -r <rate>        send rate in packets/second (client, default 1000)\n"
        << "  -z <bytes>       payload size excluding 20‑byte header (default 128)\n"
        << "  -t <timeout_us>  ACK timeout in microseconds (client, default 100000)\n"
        << "  -d <seconds>     total runtime (0 = unlimited)\n"
        << "  -m <max_in_flight> maximum packets in flight (client, default 1000)\n"
        << "  -b <batch_size>  number of packets to batch in one ACK (default max_in_flight/2)\n"
        << "  -v               verbose (per‑packet log)\n"
        << "  -u               use normal UDP sockets instead of BPF\n"
        << "  -n               no ACK mode - send continuously without waiting for or processing ACKs\n"
        << "  -n2              continuous send mode - send without waiting for ACKs but still process them\n"
        << "  -x               skip UDP socket initialization (requires BPF mode, conflicts with -u)\n"
        << "  -D               use distinct source ports (9901 client, 9902 server ACK) in BPF mode\n";
    std::exit(EXIT_FAILURE);
}

int main(int argc, char* const argv[]) {
    // Mode flags and parameters with defaults
    bool     server  = false;
    std::string dst_ip;
    uint16_t port    = 8888;
    std::string ifname;
    uint32_t rate    = 1000;   // packets per second
    size_t   payload = 128;    // bytes per packet
    uint32_t timeout = 100000; // microseconds (default 100ms)
    bool     verbose = false;
    uint32_t duration= 0;      // seconds (0 = unlimited)
    size_t   max_in_flight = 1000; // maximum packets in flight
    size_t   batch_size = 0;   // batch size (0 = use max_in_flight/2)
    bool use_udp = false;  // Default to BPF
    bool no_ack = false;   // Default to normal mode
    bool continuous_send = false;  // Default to normal mode
    bool skip_udp_sockets = false; // New flag
    bool distinct_ports = false; // New flag

    // Parse command‑line options
    int opt;
    // Add 'x' to the getopt string
    while ((opt = getopt(argc, argv, "sc:p:i:r:z:t:d:m:b:vun::xD")) != -1) { // Added 'd'
        switch (opt) {
            case 's':
                server = true;
                break;

            case 'c':
                dst_ip = optarg;
                break;

            case 'p':
                port = static_cast<uint16_t>(std::stoi(optarg));
                break;

            case 'i':
                ifname = optarg;
                break;

            case 'r':
                rate = static_cast<uint32_t>(std::stoul(optarg));
                break;

            case 'z':
                payload = std::stoul(optarg);
                break;

            case 't':
                timeout = std::stoul(optarg);
                break;

            case 'd':
                duration = std::stoul(optarg);
                break;

            case 'm':
                max_in_flight = std::stoul(optarg);
                break;

            case 'b':
                batch_size = std::stoul(optarg);
                break;

            case 'v':
                verbose = true;
                break;

            case 'u':
                use_udp = true;
                break;

            case 'n':
                if (optarg != nullptr && strcmp(optarg, "2") == 0) {
                    continuous_send = true;
                } else {
                no_ack = true;
                }
                break;

            case 'x': // Handle new flag
                 skip_udp_sockets = true;
                 break;
            case 'D': // Handle new flag
                 distinct_ports = true;
                break;

            default:
                help();
        }
    }

    // Check for incompatible options
    if (no_ack && continuous_send) {
        std::cerr << "Error: Cannot use both -n and -n2\n";
        help();
    }
    // Add check for -x and -u conflict
    if (skip_udp_sockets && use_udp) {
        std::cerr << "Error: Cannot use -x (skip UDP sockets) together with -u (use UDP mode).\n";
        help();
    }
    if (distinct_ports && use_udp) {
        std::cerr << "Warning: -D (distinct ports) flag is ignored when -u (UDP mode) is specified.\n";
        // Not a fatal error, just ignore -d in UDP mode
    }

    // Must specify either server mode or a destination IP
    if (!server && dst_ip.empty()) {
        help();
    }

    // Validate payload size
    if (payload > MAX_PAYLOAD) {
        std::cerr << "Error: Payload too large (max "
                  << MAX_PAYLOAD << " bytes)\n";
        std::exit(EXIT_FAILURE);
    }

    // If batch size not specified, use half of max_in_flight
    if (batch_size == 0) {
        batch_size = max_in_flight / 2;
    }

    // Run in the requested mode
    if (server) {
        // Pass distinct_ports to run_server
        run_server(port, payload, ifname, verbose, max_in_flight, use_udp, distinct_ports);
    } else {
        // Pass distinct_ports to run_client
        run_client(dst_ip, port, payload, ifname, rate, timeout, verbose, duration, max_in_flight, batch_size, use_udp, no_ack, continuous_send, skip_udp_sockets, distinct_ports);
    }

    return 0;
}
