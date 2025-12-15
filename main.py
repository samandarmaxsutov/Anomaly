import socket
import os
import datetime
import sys

SOCK_PATH = "/tmp/ddos_stats_socket"

# JADVAL SARLAVHASI YANGILANDI
def print_header():
    print("-" * 125)
    print(f"{'Time':<15} | {'Port':<4} | {'PPS':<8} | {'BPS':<15} | {'UDP %':<6} | {'SYN %':<6} | {'SYN-ACK %':<10} | {'FIN %':<6} | {'Anomaly Status':<20}")
    print("-" * 125)

# O'zgartirilgan start_server funksiyasi
def start_server():
    if os.path.exists(SOCK_PATH):
        os.remove(SOCK_PATH)

    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    
    try:
        server.bind(SOCK_PATH)
        server.listen(1)
        
        print(f"Server ishga tushdi: {SOCK_PATH}...")
        print("DPDK dasturidan ma'lumot kutilmoqda...\n")
        
        print_header()

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
                        if not line: continue

                        try:
                            # CSV formatini ajratamiz (8 ta ustun kutilyapti)
                            # 0:Timestamp, 1:PortID, 2:PPS, 3:BPS, 4:UDP_Rate, 5:SYN_Rate, 6:SYN_ACK_Rate, 7:FIN_Rate
                            parts = line.split(',')
                            if len(parts) != 8:
                                # Agar ustunlar soni mos kelmasa, tashlab yuboramiz
                                print(f"Format xatosi: {line}")
                                continue
                            
                            ts_ms = float(parts[0])
                            port_id = parts[1]
                            pps = float(parts[2])
                            bps = float(parts[3])
                            udp_rate = float(parts[4]) * 100  
                            syn_rate = float(parts[5]) * 100
                            syn_ack_rate = float(parts[6]) * 100 # YANGI
                            fin_rate = float(parts[7]) * 100     # YANGI

                            # ANOMALIYANI ANIQLASH (Oddiy qoida)
                            status = "OK"
                            
                            # 1. TCP SYN Flood (ko'p SYN, kam SYN-ACK)
                            if syn_rate > 50 and syn_ack_rate < 5:
                                status = "SYN FLOOD XAVFI"
                            
                            # 2. UDP Flood (yuqori UDP ulushi va PPS)
                            elif udp_rate > 80 and pps > 1000:
                                status = "UDP FLOOD XAVFI"
                            
                            # 3. Connection Exhaustion (ko'p SYN, kam FIN)
                            elif syn_rate > 30 and fin_rate < 5 and pps > 500:
                                status = "CONN EXHAUSTION XAVFI"
                            
                            # Vaqtni formatlash
                            dt_object = datetime.datetime.fromtimestamp(ts_ms / 1000.0)
                            readable_time = dt_object.strftime('%H:%M:%S.%f')[:-3]

                            # Ekranga chiroyli qilib chiqarish
                            print(f"{readable_time:<15} | {port_id:<4} | {pps:<8,.0f} | {bps:<15,.0f} | {udp_rate:<5.1f}% | {syn_rate:<5.1f}% | {syn_ack_rate:<9.1f}% | {fin_rate:<5.1f}% | {status:<20}")
                        
                        except ValueError:
                            continue

            except Exception as e:
                print(f"\nBog'lanish uzildi: {e}")
            finally:
                conn.close()

    except KeyboardInterrupt:
        print("\nDastur to'xtatildi.")
    finally:
        server.close()
        if os.path.exists(SOCK_PATH):
            os.remove(SOCK_PATH)

if __name__ == "__main__":
    start_server()