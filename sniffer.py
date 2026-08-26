import socket
import struct

def main():
    try:
        conn = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        conn.bind(("0.0.0.0", 0))
        conn.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        conn.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        
        print("[+] Network Sniffer is running... Press Ctrl+C to stop.")
        
        while True:
            raw_data, addr = conn.recvfrom(65535)
            ip_header = raw_data[0:20]
            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            
            src_ip = socket.inet_ntoa(iph[8])
            dest_ip = socket.inet_ntoa(iph[9])
            protocol = iph[6]
            
            print(f"Source IP: {src_ip} | Destination IP: {dest_ip} | Protocol: {protocol}")
            
    except KeyboardInterrupt:
        print("\n[-] Sniffer stopped.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    main()
