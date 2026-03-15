from scapy.all import IP, TCP, send

packet = IP(dst="127.0.0.1")/TCP(dport=80, flags="S")
send(packet, count=50)