#include "l2fwd_ddos_collector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <math.h>

#include <rte_ethdev.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

// Global stats array
struct ddos_stats port_ddos_stats[RTE_MAX_ETHPORTS];

// Socket Configuration
#define SOCK_PATH "/tmp/ddos_stats_socket"
static int sock_fd = -1;
static struct sockaddr_un server_addr;

/**
 * Initialize DDoS collector and socket structure
 */
void ddos_collector_init(void)
{
    printf("DDoS Collector: Initializing...\n");
    
    // Clear all stats
    memset(port_ddos_stats, 0, sizeof(port_ddos_stats));
    
    // Setup the socket address structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH, sizeof(server_addr.sun_path) - 1);
    
    printf("DDoS Collector: Initialized successfully\n");
}

/**
 * Helper to manage socket connection (lazy connection)
 */
static void check_and_connect_socket(void)
{
    if (sock_fd >= 0) return; // Already connected

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("DDoS Collector: Failed to create socket");
        return;
    }

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) < 0) {
        // Connection failed (Python script might not be running yet)
        close(sock_fd);
        sock_fd = -1;
    } else {
        printf("DDoS Collector: Connected to Python receiver at %s\n", SOCK_PATH);
    }
}

/**
 * Helper: Add unique IP address to tracking set
 * Uses simple linear search (efficient for reasonable IP counts)
 */
static void add_unique_ip(struct ddos_stats *stats, uint32_t ip)
{
    // Check if we've hit the limit
    if (stats->unique_ip_count >= MAX_UNIQUE_IPS) return;
    
    // Check if IP already exists
    for (uint32_t i = 0; i < stats->unique_ip_count; i++) {
        if (stats->unique_src_ips[i] == ip) {
            return; // Already tracked
        }
    }
    
    // Add new unique IP
    stats->unique_src_ips[stats->unique_ip_count++] = ip;
}

/**
 * Helper: Add unique port to tracking set
 */
static void add_unique_port(struct ddos_stats *stats, uint16_t port)
{
    // Check if we've hit the limit
    if (stats->unique_port_count >= MAX_UNIQUE_PORTS) return;
    
    // Check if port already exists
    for (uint32_t i = 0; i < stats->unique_port_count; i++) {
        if (stats->unique_ports[i] == port) {
            return; // Already tracked
        }
    }
    
    // Add new unique port
    stats->unique_ports[stats->unique_port_count++] = port;
}

/**
 * Helper: Get packet size bucket index for histogram
 * Buckets: <64, 64-127, 128-255, 256-511, 512-1023, 1024-1499, >=1500
 */
static uint8_t get_size_bucket(uint32_t size)
{
    if (size < 64) return 0;
    if (size < 128) return 1;
    if (size < 256) return 2;
    if (size < 512) return 3;
    if (size < 1024) return 4;
    if (size < 1500) return 5;
    return 6;
}

/**
 * Main packet statistics collection function
 * Called for each received packet
 */
void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;
    struct rte_udp_hdr *udp_hdr;

    if (unlikely(portid >= RTE_MAX_ETHPORTS)) return;

    // 1. Update total packet and byte count
    port_ddos_stats[portid].total_pkts++;
    port_ddos_stats[portid].total_bytes += m->pkt_len;
    
    // 2. Update size histogram for entropy calculation
    uint8_t bucket = get_size_bucket(m->pkt_len);
    port_ddos_stats[portid].size_buckets[bucket]++;

    // 3. Parse Ethernet header
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    
    // Only process IPv4 packets
    if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
        port_ddos_stats[portid].other_pkts++;
        return;
    }

    // 4. Parse IP header
    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, 
                                        sizeof(struct rte_ether_hdr));
    
    // Track unique source IP address
    uint32_t src_ip = rte_be_to_cpu_32(ipv4_hdr->src_addr);
    add_unique_ip(&port_ddos_stats[portid], src_ip);
    
    // 5. Process based on protocol type
    switch (ipv4_hdr->next_proto_id) {
    case IPPROTO_UDP:
        port_ddos_stats[portid].udp_pkts++;
        
        // Parse UDP header to track destination ports
        udp_hdr = (struct rte_udp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint16_t udp_dst_port = rte_be_to_cpu_16(udp_hdr->dst_port);
        add_unique_port(&port_ddos_stats[portid], udp_dst_port);
        break;
        
    case IPPROTO_TCP:
        port_ddos_stats[portid].tcp_pkts++;
        
        // Parse TCP header
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        uint8_t tcp_flags = tcp_hdr->tcp_flags;
        
        // Track TCP destination port
        uint16_t tcp_dst_port = rte_be_to_cpu_16(tcp_hdr->dst_port);
        add_unique_port(&port_ddos_stats[portid], tcp_dst_port);
        
        // Count individual TCP flags
        if (tcp_flags & RTE_TCP_SYN_FLAG) {
            port_ddos_stats[portid].syn_pkts++;
        }
        
        if ((tcp_flags & RTE_TCP_SYN_FLAG) && (tcp_flags & RTE_TCP_ACK_FLAG)) {
            port_ddos_stats[portid].syn_ack_pkts++;
        }
        
        if (tcp_flags & RTE_TCP_ACK_FLAG) {
            port_ddos_stats[portid].ack_pkts++;
        }

        if (tcp_flags & RTE_TCP_FIN_FLAG) {
            port_ddos_stats[portid].fin_pkts++;
        }
        
        if (tcp_flags & RTE_TCP_RST_FLAG) {
            port_ddos_stats[portid].rst_pkts++;
        }
        break;
        
    case IPPROTO_ICMP:
        port_ddos_stats[portid].icmp_pkts++;
        break;
        
    default:
        port_ddos_stats[portid].other_pkts++;
        break;
    }
}

/**
 * Helper: Calculate Shannon entropy for a histogram
 * Used for measuring distribution uniformity
 */
static double calculate_entropy(uint32_t *buckets, uint32_t num_buckets, uint64_t total)
{
    if (total == 0) return 0.0;
    
    double entropy = 0.0;
    for (uint32_t i = 0; i < num_buckets; i++) {
        if (buckets[i] > 0) {
            double probability = (double)buckets[i] / (double)total;
            entropy -= probability * log2(probability);
        }
    }
    return entropy;
}

/**
 * Calculate IP entropy as a measure of IP diversity
 * Higher entropy = more distributed sources
 */
static double calculate_ip_entropy(struct ddos_stats *stats)
{
    if (stats->unique_ip_count == 0 || stats->total_pkts == 0) {
        return 0.0;
    }
    
    // Simple entropy proxy: log2(total_packets / unique_ips)
    // This gives us an idea of how distributed the traffic is
    double ratio = (double)stats->total_pkts / (double)stats->unique_ip_count;
    return log2(ratio);
}

/**
 * Calculate port entropy as a measure of port diversity
 * Used to detect port scans
 */
static double calculate_port_entropy(struct ddos_stats *stats)
{
    if (stats->unique_port_count == 0) {
        return 0.0;
    }
    
    // Entropy based on number of unique ports
    return log2((double)stats->unique_port_count);
}

/**
 * Main logging and statistics export function
 * Called periodically to send stats to Python analyzer
 */
void ddos_log_and_reset_stats(void)
{
    unsigned portid;
    struct timespec ts;
    long long timestamp_ms;
    struct rte_eth_dev_info dev_info;
    char buffer[2048];
    int len;

    // Ensure socket connection
    check_and_connect_socket();

    // Get current timestamp
    clock_gettime(CLOCK_REALTIME, &ts);
    timestamp_ms = (long long)ts.tv_sec * 1000LL + (long long)ts.tv_nsec / 1000000LL;

    // Iterate over all active ports
    RTE_ETH_FOREACH_DEV(portid) {
        if (rte_eth_dev_info_get(portid, &dev_info) != 0) continue;

        // Time period in seconds
        double time_sec = (double)STATS_PERIOD_US / 1000000.0;
        
        // Avoid division by zero
        double total_safe = (port_ddos_stats[portid].total_pkts > 0) 
                            ? (double)port_ddos_stats[portid].total_pkts 
                            : 1.0;
        
        // ===== CALCULATE ALL FEATURES =====
        
        // 1. Packet rates
        double pps = (double)port_ddos_stats[portid].total_pkts / time_sec;
        double udp_pps = (double)port_ddos_stats[portid].udp_pkts / time_sec;
        double syn_pps = (double)port_ddos_stats[portid].syn_pkts / time_sec;
        
        // 2. Protocol ratios
        double udp_ratio = (double)port_ddos_stats[portid].udp_pkts / total_safe;
        double syn_ratio = (double)port_ddos_stats[portid].syn_pkts / total_safe;
        double ack_ratio = (double)port_ddos_stats[portid].ack_pkts / total_safe;
        double fin_ratio = (double)port_ddos_stats[portid].fin_pkts / total_safe;
        double rst_ratio = (double)port_ddos_stats[portid].rst_pkts / total_safe;
        double icmp_rate = (double)port_ddos_stats[portid].icmp_pkts / total_safe;
        
        // 3. Bandwidth
        double bps = (double)port_ddos_stats[portid].total_bytes * 8.0 / time_sec;
        
        // 4. Unique counters
        uint32_t unique_src_ips = port_ddos_stats[portid].unique_ip_count;
        
        // 5. Entropy calculations
        double entropy_ip = calculate_ip_entropy(&port_ddos_stats[portid]);
        double entropy_port = calculate_port_entropy(&port_ddos_stats[portid]);
        double size_entropy = calculate_entropy(port_ddos_stats[portid].size_buckets, 
                                                 16, 
                                                 port_ddos_stats[portid].total_pkts);

        // ===== FORMAT CSV OUTPUT =====
        // Format: Timestamp,PortID,pps,udp_pps,syn_pps,udp_ratio,unique_src_ips,
        //         entropy_ip,bps,entropy_port,ack_ratio,fin_ratio,rst_ratio,
        //         syn_ratio,icmp_rate,size_entropy
        len = snprintf(buffer, sizeof(buffer), 
                       "%lld,%u,%.2f,%.2f,%.2f,%.6f,%u,%.6f,%.2f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
                       timestamp_ms,           // Timestamp in milliseconds
                       portid,                 // Port ID
                       pps,                    // Packets per second
                       udp_pps,                // UDP packets per second
                       syn_pps,                // SYN packets per second
                       udp_ratio,              // UDP ratio (0-1)
                       unique_src_ips,         // Number of unique source IPs
                       entropy_ip,             // IP address entropy
                       bps,                    // Bits per second
                       entropy_port,           // Port entropy
                       ack_ratio,              // ACK ratio (0-1)
                       fin_ratio,              // FIN ratio (0-1)
                       rst_ratio,              // RST ratio (0-1)
                       syn_ratio,              // SYN ratio (0-1)
                       icmp_rate,              // ICMP rate (0-1)
                       size_entropy);          // Packet size entropy

        // ===== SEND TO PYTHON VIA SOCKET =====
        if (sock_fd >= 0) {
            if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                // Socket error - close and will try to reconnect next time
                perror("DDoS Collector: Failed to send data");
                close(sock_fd);
                sock_fd = -1;
            }
        }

        // ===== RESET COUNTERS FOR NEXT PERIOD =====
        memset(&port_ddos_stats[portid], 0, sizeof(struct ddos_stats));
    }
}