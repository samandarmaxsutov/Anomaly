#  main.py - DDoS Detection Server with Adaptive Algorithms
import socket
import os
import datetime
import sys
import time
import math
import csv
from collections import defaultdict, Counter
import numpy as np

SOCK_PATH = "/tmp/ddos_stats_socket"
OUTPUT_CSV = "dpdk_detection_log.csv"

# --- Detection Parameters ---
AGG_INTERVAL = 1.0          # Stats collection interval (1 second)
WARMUP_SECONDS = 30         # Baseline learning period
CUSUM_k = 0.3               # CUSUM slack parameter
CUSUM_h = 22.0              # CUSUM alarm threshold
EWMA_ALPHA = 0.1            # EWMA smoothing factor
SPOOF_Z_THRESHOLD = 3.0     # Z-score threshold for anomalies
MIN_PPS_FOR_CHECK = 10.0    # Minimum PPS to trigger detection

# Feature names matching C code output
FEATURES = ["pps", "udp_pps", "syn_pps", "udp_ratio", "unique_src_ips", "entropy_ip",
            "bps", "entropy_port", "ack_ratio", "fin_ratio", "rst_ratio",
            "syn_ratio", "icmp_rate", "size_entropy"]

# Features tracked by CUSUM (volume/ratio increases)
CUSUM_FEATURES = ["pps", "udp_pps", "syn_pps", "udp_ratio", "bps", "ack_ratio", 
                  "fin_ratio", "rst_ratio", "syn_ratio", "icmp_rate"]

# Features tracked by Z-Score (distribution anomalies)
ENTROPY_FEATURES = ["unique_src_ips", "entropy_ip", "entropy_port", "size_entropy"]

# --- Global State ---
history = {f: [] for f in FEATURES}
timestamps = []
cusum_state = {f: 0.0 for f in CUSUM_FEATURES}
baseline_mu = {}
baseline_sigma = {}
warmup_complete = False
csv_header_written = False

def print_header():
    print("=" * 200)
    print(f"{'Time':<15} | {'Port':<4} | {'PPS':<10} | {'BPS':<15} | {'UDP%':<6} | "
          f"{'SYN%':<6} | {'ACK%':<6} | {'FIN%':<6} | {'RST%':<6} | "
          f"{'IPs':<6} | {'E_IP':<6} | {'E_Port':<7} | {'CUSUM':<6} | {'SPOOF':<6} | {'Status':<25}")
    print("=" * 200)

def update_ewma_baseline(current_values):
    """Update adaptive baseline using EWMA for mean and variance"""
    global baseline_mu, baseline_sigma
    
    all_tracked = CUSUM_FEATURES + ENTROPY_FEATURES
    
    for f in all_tracked:
        if f in baseline_mu:
            x_t = current_values[f]
            
            # Update mean
            mu_old = baseline_mu[f]
            mu_new = EWMA_ALPHA * x_t + (1.0 - EWMA_ALPHA) * mu_old
            baseline_mu[f] = mu_new
            
            # Update variance
            var_old = baseline_sigma[f] ** 2
            squared_error = (x_t - mu_new) ** 2
            var_new = EWMA_ALPHA * squared_error + (1.0 - EWMA_ALPHA) * var_old
            baseline_sigma[f] = math.sqrt(var_new) + 1e-8

def compute_baseline():
    """Compute initial baseline from warmup period"""
    global baseline_mu, baseline_sigma, warmup_complete
    
    print(f"\n[*] Computing baseline from {WARMUP_SECONDS}s warmup period...")
    
    all_tracked = CUSUM_FEATURES + ENTROPY_FEATURES
    
    for f in all_tracked:
        if len(history[f]) > 0:
            arr = np.array(history[f], dtype=float)
            baseline_mu[f] = arr.mean()
            baseline_sigma[f] = arr.std(ddof=0) + 1e-8
            print(f"    {f}: μ={baseline_mu[f]:.4f}, σ={baseline_sigma[f]:.4f}")
    
    warmup_complete = True
    print("[*] Baseline established. Detection active.\n")

def run_cusum(values):
    """CUSUM algorithm for detecting sustained increases"""
    alarm = False
    alarms = []
    
    for f in CUSUM_FEATURES:
        if f not in baseline_mu:
            continue
            
        x = values[f]
        mu0 = baseline_mu[f]
        sigma0 = baseline_sigma[f]
        
        k = CUSUM_k * sigma0
        h = CUSUM_h * sigma0
        
        s_old = cusum_state[f]
        s_new = max(0.0, s_old + (x - mu0) - k)
        cusum_state[f] = s_new
        
        if s_new > h:
            alarm = True
            alarms.append(f)
            cusum_state[f] = 0.0
    
    return alarm, alarms

def run_zscore_detection(values):
    """Adaptive Z-Score detection for distribution anomalies"""
    if values["pps"] < MIN_PPS_FOR_CHECK:
        return False, []
    
    alarm = False
    alarms = []
    
    for f in ENTROPY_FEATURES:
        if f not in baseline_mu:
            continue
            
        val = values[f]
        mu = baseline_mu[f]
        sigma = baseline_sigma[f]
        
        z_score = (val - mu) / sigma
        
        # Different thresholds for different features
        if f == "size_entropy":
            # Low entropy = uniform packet sizes (attack)
            if z_score < -SPOOF_Z_THRESHOLD:
                alarm = True
                alarms.append(f"{f}(low)")
        elif f in ["entropy_ip", "entropy_port"]:
            # High entropy = spoofing/scanning
            if z_score > SPOOF_Z_THRESHOLD:
                alarm = True
                alarms.append(f"{f}(high)")
        elif f == "unique_src_ips":
            # Many unique IPs = distributed attack
            if z_score > SPOOF_Z_THRESHOLD:
                alarm = True
                alarms.append(f"{f}(high)")
    
    return alarm, alarms

def detect_anomaly(stats):
    """Combined detection using CUSUM + Z-Score"""
    global warmup_complete
    
    # Basic rule-based detection (always active)
    pps = stats['pps']
    udp_ratio = stats['udp_ratio'] * 100
    syn_ratio = stats['syn_ratio'] * 100
    ack_ratio = stats['ack_ratio'] * 100
    fin_ratio = stats['fin_ratio'] * 100
    rst_ratio = stats['rst_ratio'] * 100
    icmp_rate = stats['icmp_rate'] * 100
    unique_ips = stats['unique_src_ips']
    entropy_ip = stats['entropy_ip']
    entropy_port = stats['entropy_port']
    
    # Rule-based alarms (immediate response)
    rule_alarm = False
    rule_type = ""
    
    if syn_ratio > 60 and ack_ratio < 10 and pps > 1000:
        rule_alarm = True
        rule_type = "SYN_FLOOD"
    elif udp_ratio > 85 and pps > 5000:
        rule_alarm = True
        rule_type = "UDP_FLOOD"
    elif icmp_rate > 60 and pps > 1000:
        rule_alarm = True
        rule_type = "ICMP_FLOOD"
    elif rst_ratio > 40 and pps > 500:
        rule_alarm = True
        rule_type = "RST_FLOOD"
    
    # Adaptive detection (after warmup)
    cusum_alarm = False
    zscore_alarm = False
    cusum_features = []
    zscore_features = []
    
    if warmup_complete:
        cusum_alarm, cusum_features = run_cusum(stats)
        zscore_alarm, zscore_features = run_zscore_detection(stats)
        
        # Combined alarm: Both methods agree OR rule-based triggers
        final_alarm = rule_alarm or (cusum_alarm and zscore_alarm)
        
        # Update baseline only during normal traffic
        if not final_alarm:
            update_ewma_baseline(stats)
    else:
        final_alarm = rule_alarm
    
    # Determine status and severity
    if rule_alarm:
        status = f"⚠️  {rule_type}"
        severity = "HIGH"
    elif cusum_alarm and zscore_alarm:
        status = f"⚠️  ADAPTIVE ALARM"
        severity = "MEDIUM"
    elif cusum_alarm:
        status = "⚠️  VOLUME ANOMALY"
        severity = "LOW"
    elif zscore_alarm:
        status = "⚠️  DISTRIBUTION ANOMALY"
        severity = "LOW"
    elif pps > 100:
        status = "✓  NORMAL"
        severity = "OK"
    else:
        status = "✓  LOW TRAFFIC"
        severity = "OK"
    
    return {
        'status': status,
        'severity': severity,
        'final_alarm': final_alarm,
        'rule_alarm': rule_alarm,
        'cusum_alarm': cusum_alarm,
        'zscore_alarm': zscore_alarm,
        'cusum_features': cusum_features,
        'zscore_features': zscore_features
    }

def format_traffic_stats(stats):
    """Format statistics for display"""
    return {
        'pps': f"{stats['pps']:,.0f}",
        'bps': f"{stats['bps']:,.0f}",
        'udp_ratio': f"{stats['udp_ratio']*100:.1f}",
        'syn_ratio': f"{stats['syn_ratio']*100:.1f}",
        'ack_ratio': f"{stats['ack_ratio']*100:.1f}",
        'fin_ratio': f"{stats['fin_ratio']*100:.1f}",
        'rst_ratio': f"{stats['rst_ratio']*100:.1f}",
        'unique_ips': stats['unique_src_ips'],
        'entropy_ip': f"{stats['entropy_ip']:.2f}",
        'entropy_port': f"{stats['entropy_port']:.2f}",
    }

def append_csv_log(timestamp, port_id, stats, detection):
    """Log to CSV file"""
    global csv_header_written
    
    write_header = not csv_header_written
    
    with open(OUTPUT_CSV, 'a', newline='') as f:
        fieldnames = ['timestamp', 'port'] + FEATURES + [
            'rule_alarm', 'cusum_alarm', 'zscore_alarm', 'final_alarm'
        ]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        
        if write_header:
            writer.writeheader()
            csv_header_written = True
        
        row = {
            'timestamp': timestamp,
            'port': port_id,
            **stats,
            'rule_alarm': int(detection['rule_alarm']),
            'cusum_alarm': int(detection['cusum_alarm']),
            'zscore_alarm': int(detection['zscore_alarm']),
            'final_alarm': int(detection['final_alarm'])
        }
        writer.writerow(row)

def start_server():
    """Start Unix socket server to receive stats from DPDK"""
    global warmup_complete
    
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        server.bind(SOCK_PATH)
        server.listen(1)
        
        print("=" * 100)
        print(f"DDoS Detection Server with Adaptive Algorithms")
        print(f"Socket Path: {SOCK_PATH}")
        print(f"Warmup Period: {WARMUP_SECONDS}s | CUSUM(k={CUSUM_k}, h={CUSUM_h}) | Z-Score(σ={SPOOF_Z_THRESHOLD})")
        print(f"CSV Output: {OUTPUT_CSV}")
        print("=" * 100)
        print(f"\nWaiting for DPDK connection...\n")
        
        print_header()
        
        start_time = time.time()

        while True:
            conn, _ = server.accept()
            
            try:
                buffer = ""
                while True:
                    data = conn.recv(4096)
                    if not data:
                        break
                    
                    buffer += data.decode('utf-8')

                    while '\n' in buffer:
                        line, buffer = buffer.split('\n', 1)
                        line = line.strip()
                        if not line:
                            continue

                        try:
                            parts = line.split(',')
                            if len(parts) != 16:
                                print(f"[ERROR] Invalid format: expected 16 fields, got {len(parts)}")
                                continue
                            
                            ts_ms = float(parts[0])
                            port_id = parts[1]
                            
                            stats = {
                                'pps': float(parts[2]),
                                'udp_pps': float(parts[3]),
                                'syn_pps': float(parts[4]),
                                'udp_ratio': float(parts[5]),
                                'unique_src_ips': int(parts[6]),
                                'entropy_ip': float(parts[7]),
                                'bps': float(parts[8]),
                                'entropy_port': float(parts[9]),
                                'ack_ratio': float(parts[10]),
                                'fin_ratio': float(parts[11]),
                                'rst_ratio': float(parts[12]),
                                'syn_ratio': float(parts[13]),
                                'icmp_rate': float(parts[14]),
                                'size_entropy': float(parts[15])
                            }
                            
                            # Update history
                            timestamps.append(ts_ms / 1000.0)
                            for f in FEATURES:
                                history[f].append(stats[f])
                            
                            # Check if warmup is complete
                            elapsed = time.time() - start_time
                            if not warmup_complete and elapsed >= WARMUP_SECONDS:
                                compute_baseline()
                            
                            # Detect anomalies
                            detection = detect_anomaly(stats)
                            
                            # Format timestamp
                            dt_object = datetime.datetime.fromtimestamp(ts_ms / 1000.0)
                            readable_time = dt_object.strftime('%H:%M:%S.%f')[:-3]
                            
                            # Format statistics
                            fmt = format_traffic_stats(stats)
                            
                            # Color coding
                            status = detection['status']
                            if detection['severity'] == "HIGH":
                                status = f"\033[91m{status}\033[0m"
                            elif detection['severity'] == "MEDIUM":
                                status = f"\033[93m{status}\033[0m"
                            elif detection['severity'] == "LOW":
                                status = f"\033[96m{status}\033[0m"
                            else:
                                status = f"\033[92m{status}\033[0m"
                            
                            # Print formatted output
                            cusum_mark = "✓" if detection['cusum_alarm'] else "-"
                            zscore_mark = "✓" if detection['zscore_alarm'] else "-"
                            
                            print(f"{readable_time:<15} | {port_id:<4} | {fmt['pps']:<10} | {fmt['bps']:<15} | "
                                  f"{fmt['udp_ratio']:<5}% | {fmt['syn_ratio']:<5}% | {fmt['ack_ratio']:<5}% | "
                                  f"{fmt['fin_ratio']:<5}% | {fmt['rst_ratio']:<5}% | "
                                  f"{fmt['unique_ips']:<6} | {fmt['entropy_ip']:<6} | {fmt['entropy_port']:<7} | "
                                  f"{cusum_mark:<6} | {zscore_mark:<6} | {status:<25}")
                            
                            # Log to CSV
                            append_csv_log(ts_ms, port_id, stats, detection)
                        
                        except (ValueError, IndexError) as e:
                            print(f"[ERROR] Parse error: {e}")
                            continue

            except Exception as e:
                print(f"\n[ERROR] Connection error: {e}")
            finally:
                conn.close()

    except KeyboardInterrupt:
        print("\n\n[INFO] Server stopped by user (Ctrl+C)")
    except Exception as e:
        print(f"\n[ERROR] Server error: {e}")
    finally:
        server.close()
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)
        print("[INFO] Cleanup complete")

if __name__ == "__main__":
    start_server()