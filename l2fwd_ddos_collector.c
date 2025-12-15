#include "l2fwd_ddos_collector.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

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

// Initialize the socket structure (try to connect later to avoid startup blocking)
void ddos_collector_init(void)
{
    printf("DDoS Collector: Initializing...\n");

    // Setup the socket address structure
    memset(&server_addr, 0, sizeof(struct sockaddr_un));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, SOCK_PATH, sizeof(server_addr.sun_path) - 1);
}

// Helper to manage socket connection
static void check_and_connect_socket(void)
{
    if (sock_fd >= 0) return; // Already connected

    sock_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock_fd < 0) {
        perror("DDoS Collector: Failed to create socket");
        return;
    }

    // Set non-blocking to prevent freezing the packet forwarding if Python is slow
    // (Optional but recommended for high performance apps)
    // fcntl(sock_fd, F_SETFL, O_NONBLOCK); 

    if (connect(sock_fd, (struct sockaddr *)&server_addr, sizeof(struct sockaddr_un)) < 0) {
        // Connection failed (Python script might not be running)
        // Close it so we try again next time
        close(sock_fd);
        sock_fd = -1;
    } else {
        printf("DDoS Collector: Connected to Python receiver at %s\n", SOCK_PATH);
    }
}

void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid)
{
    struct rte_ether_hdr *eth_hdr;
    struct rte_ipv4_hdr *ipv4_hdr;
    struct rte_tcp_hdr *tcp_hdr;

    if (unlikely(portid >= RTE_MAX_ETHPORTS)) return;

    // 1. Update total packet and byte count
    port_ddos_stats[portid].total_pkts++;
    port_ddos_stats[portid].total_bytes += m->pkt_len;

    // 2. Check for EtherType (IPv4 only)
    eth_hdr = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);
    if (rte_be_to_cpu_16(eth_hdr->ether_type) != RTE_ETHER_TYPE_IPV4) {
        port_ddos_stats[portid].other_pkts++;
        return;
    }

    // 3. Check IP protocol
    ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    
    switch (ipv4_hdr->next_proto_id) {
    case IPPROTO_UDP:
        port_ddos_stats[portid].udp_pkts++;
        break;
    case IPPROTO_TCP:
        port_ddos_stats[portid].tcp_pkts++;
        
        // 4. Check for TCP flags
        tcp_hdr = (struct rte_tcp_hdr *)((char *)ipv4_hdr + (ipv4_hdr->ihl * 4));
        
        uint8_t flags = tcp_hdr->tcp_flags; // Qulaylik uchun

        // SYN flag
        if (flags & RTE_TCP_SYN_FLAG)
            port_ddos_stats[portid].syn_pkts++;
            
        // SYN-ACK flag (Bog'lanish o'rnatish javobi)
        if ((flags & RTE_TCP_SYN_FLAG) && (flags & RTE_TCP_ACK_FLAG))
            port_ddos_stats[portid].syn_ack_pkts++;

        // FIN flag (Bog'lanishni tugatish)
        if (flags & RTE_TCP_FIN_FLAG)
            port_ddos_stats[portid].fin_pkts++;

        break;
    case IPPROTO_ICMP:
        port_ddos_stats[portid].icmp_pkts++;
        break;
    default:
        port_ddos_stats[portid].other_pkts++;
        break;
    }
}

void ddos_log_and_reset_stats(void)
{
    unsigned portid;
    struct timespec ts;
    long long timestamp_ms;
    struct rte_eth_dev_info dev_info;
    char buffer[1024];
    int len;

    // Ensure we are connected
    check_and_connect_socket();

    // Get current time
    clock_gettime(CLOCK_REALTIME, &ts);
    timestamp_ms = (long long)ts.tv_sec * 1000 + (long long)ts.tv_nsec / 1000000;

    // Iterate over all ports
RTE_ETH_FOREACH_DEV(portid) {
        if (rte_eth_dev_info_get(portid, &dev_info) != 0) continue;

        // Calculate rates
        double time_sec = (double)STATS_PERIOD_US / 1000000.0;
        double pps = (double)port_ddos_stats[portid].total_pkts / time_sec;
        double bps = (double)port_ddos_stats[portid].total_bytes * 8.0 / time_sec;
        
        double total_safe = (port_ddos_stats[portid].total_pkts > 0) ? (double)port_ddos_stats[portid].total_pkts : 1.0;
        
        // Calculate rates relative to total packets
        double udp_rate = (double)port_ddos_stats[portid].udp_pkts / total_safe;
        double syn_rate = (double)port_ddos_stats[portid].syn_pkts / total_safe;
        
        // --- YANGI HISOBLASH ---
        double syn_ack_rate = (double)port_ddos_stats[portid].syn_ack_pkts / total_safe;
        double fin_rate = (double)port_ddos_stats[portid].fin_pkts / total_safe;
        // -----------------------

        // Format data into CSV string: 
        // Timestamp,PortID,PPS,BPS,UDP_Rate,SYN_Rate,SYN_ACK_Rate,FIN_Rate
        len = snprintf(buffer, sizeof(buffer), "%lld,%u,%.2f,%.2f,%.4f,%.4f,%.4f,%.4f\n",
                       timestamp_ms, 
                       portid, 
                       pps, 
                       bps, 
                       udp_rate, 
                       syn_rate,
                       syn_ack_rate,  // <-- YANGI
                       fin_rate);     // <-- YANGI

        // Send to Python via Socket
        if (sock_fd >= 0) {
            if (send(sock_fd, buffer, len, MSG_NOSIGNAL) < 0) {
                // ... (socket error handling) ...
                close(sock_fd);
                sock_fd = -1;
            }
        }
    

        // Reset counters
        memset(&port_ddos_stats[portid], 0, sizeof(struct ddos_stats));
    }
}