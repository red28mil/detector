import dpkt
import socket

def detect_incomplete_syn(pcap_file, output_file):
    """
    Detects incomplete SYN packets, i.e., SYN packets without corresponding SYN-ACKs.

    Args:
        pcap_file: Path to the PCAP file.
        output_file: Path to the output file.
    """

    syn_sent = set()
    syn_ack_received = set()

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        for ts, buf in pcap:
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                ip = eth.data

               
                if not isinstance(ip, dpkt.ip.IP):
                    continue

                tcp = ip.data

                if not isinstance(tcp, dpkt.tcp.TCP):
                    continue

                src_ip = socket.inet_ntoa(ip.src)  
                dst_ip = socket.inet_ntoa(ip.dst)

                if tcp.flags & dpkt.tcp.TH_SYN:
                    syn_sent.add(src_ip)
                elif tcp.flags & (dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK):
                    syn_ack_received.add(dst_ip)
            except dpkt.dpkt.NeedData:
               
                continue

    incomplete_syn_ips = syn_sent - syn_ack_received

    with open(output_file, 'w') as f:
        for ip in incomplete_syn_ips:
            f.write(f"Incomplete SYN packet detected from IP: {ip}\n")
            print(f"Incomplete SYN packet detected from IP: {ip}")

if __name__ == '__main__':
    pcap_file = 'captures.pcap'  
    output_file = 'mil.txt'
    detect_incomplete_syn(pcap_file, output_file)