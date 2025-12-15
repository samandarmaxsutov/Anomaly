#ifndef __L2FWD_DDOS_COLLECTOR_H__
#define __L2FWD_DDOS_COLLECTOR_H__

#include <stdint.h>
#include <rte_mbuf.h>

// Time period over which statistics are collected (1 second)
#define STATS_PERIOD_US 1000000ULL

struct ddos_stats {
    uint64_t total_pkts;
    uint64_t total_bytes;
    
    // Protocol-specific counters
    uint64_t udp_pkts;
    uint64_t tcp_pkts;
    uint64_t icmp_pkts;
    uint64_t other_pkts;
    
    // --- YANGI TCP FLAG COUNTERLAR ---
    uint64_t syn_pkts;      // TCP SYN (Yangi bog'lanish boshlanishi)
    uint64_t syn_ack_pkts;  // TCP SYN-ACK (Server javobi)
    uint64_t fin_pkts;      // TCP FIN (Bog'lanish tugashi)
    // ---------------------------------
};

extern struct ddos_stats port_ddos_stats[RTE_MAX_ETHPORTS];

void ddos_collect_packet_stats(struct rte_mbuf *m, unsigned portid);
void ddos_log_and_reset_stats(void);
void ddos_collector_init(void);

#endif /* __L2FWD_DDOS_COLLECTOR_H__ */