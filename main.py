from scapy.all import *
import os
from argparser import get_cli_args
import socket


class Sniffer:
    def __init__(self, protocol, port):
        self.ips = {}
        self.protocol = protocol
        self.port = port

    def getPktCount(self, ip):
        cnt = 0
        for sport in self.ips[ip]["sports"]:
            cnt += self.ips[ip]["sports"][sport]
        return cnt

    def printIP(self, ip):
        try:
            reverse_dns = socket.gethostbyaddr(ip)[0]
        except:
            reverse_dns = "unresolvable"

        print("IP: " + ip + " (" + reverse_dns + ")")
        print("Total packets: " + str(self.getPktCount(ip)))
        print("\tSource Ports:")
        if "sports" in self.ips[ip]:
            for sport in self.ips[ip]["sports"]:
                print("\t\t" + str(sport) + ": " + str(self.ips[ip]["sports"][sport]))
        else:
            print("\t\tNone")

        print("\tDestination Ports:")
        if "dports" in self.ips[ip]:
            for dport in self.ips[ip]["dports"]:
                print("\t\t" + str(dport) + ": " + str(self.ips[ip]["dports"][dport]))
        else:
            print("\t\tNone")

    def print_ips(self):
        os.system('cls')
        for ip in self.ips:
            self.printIP(ip)

    def print_summary(self, pkt):
        if IP in pkt:
            ip_src = pkt[IP].src
            ip_dst = pkt[IP].dst
        else:
            return

        if self.protocol in pkt:
            tcp_sport = pkt[TCP].sport
            tcp_dport = pkt[TCP].dport

            if tcp_sport == self.port or tcp_dport == self.port:
                if ip_src not in self.ips:
                    self.ips[ip_src] = {}
                if ip_dst not in self.ips:
                    self.ips[ip_dst] = {}

                if "sports" not in self.ips[ip_src]:
                    self.ips[ip_src]["sports"] = {}
                if "sports" not in self.ips[ip_dst]:
                    self.ips[ip_dst]["sports"] = {}

                if "dports" not in self.ips[ip_dst]:
                    self.ips[ip_dst]["dports"] = {}
                if "dports" not in self.ips[ip_src]:
                    self.ips[ip_src]["dports"] = {}

                if tcp_sport not in self.ips[ip_src]["sports"]:
                    self.ips[ip_src]["sports"][tcp_sport] = 0
                if tcp_dport not in self.ips[ip_dst]["sports"]:
                    self.ips[ip_dst]["sports"][tcp_dport] = 0

                if tcp_sport not in self.ips[ip_dst]["dports"]:
                    self.ips[ip_dst]["dports"][tcp_sport] = 0
                if tcp_dport not in self.ips[ip_src]["dports"]:
                    self.ips[ip_src]["dports"][tcp_dport] = 0

                self.ips[ip_src]["sports"][tcp_sport] += 1
                self.ips[ip_src]["dports"][tcp_dport] += 1

                self.ips[ip_dst]["sports"][tcp_dport] += 1
                self.ips[ip_dst]["dports"][tcp_sport] += 1

            self.print_ips()

    def sniff(self):
        sniff(filter="ip", prn=self.print_summary)


def main():
    args = get_cli_args()
    protocol = args.protocol.upper()
    port = int(args.port)
    s = Sniffer(protocol, port)
    s.sniff()


main()

# or it possible to filter with filter parameter...!
# sniff(filter="ip and host 192.168.0.1",prn=print_summary)
