#ifndef __L2FWD_DDOS_COLLECTOR_H__
#define __L2FWD_DDOS_COLLECTOR_H__

#include <stdint.h>
#include <rte_mbuf.h>

// Time period over which statistics are collected (1 second)
#define STATS_PERIOD_US 1000000ULL

// Maximum unique IPs to track per port
#define MAX_UNIQUE_IPS 65536
#define MAX_UNIQUE_PORTS 65536

struct ddos_stats {
    uint64_t total_pkts;
    uint64_t total_bytes;
    
    // Protocol-specific counters
    uint64_t udp_pkts;
    uint64_t tcp_pkts;
    uint64_t icmp_pkts;
    uint64_t other_pkts;
    
    // TCP flag counters
    uint64_t syn_pkts;
    uint64_t syn_ack_pkts;
    uint64_t ack_pkts;
    uint64_t fin_pkts;
    uint64_t rst_pkts;
    
    // Unique IP tracking (simple hash set)
    uint32_t unique_src_ips[MAX_UNIQUE_IPS];
    uint32_t unique_ip_count;
    
    // Port tracking for entropy
    uint16_t unique_ports[MAX_UNIQUE_PORTS];
    uint32_t unique_port_count;
    
    // Packet size histogram (for entropy calculation)
    uint32_t size_buckets[16];  // 16 size ranges
};

extern struct ddos_stats port_ddos_stats[RTE_MAX_ETHPORTS];

void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);
void ddos_collector_init(void);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */