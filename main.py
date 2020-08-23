from scapy.all import *
import os
from argparser import get_cli_args
import socket


class Sniffer:
    def __init__(self, protocol, port):
        self.ips = {}
        self.protocol = protocol
        self.port = port

    def initIPDict(self, ip_src, ip_dst):
        if ip_src not in self.ips:
            self.ips[ip_src] = {}
        if ip_dst not in self.ips:
            self.ips[ip_dst] = {}

    def initPortDict(self, ip_src, ip_dst, sport, dport):
        if "sports" not in self.ips[ip_src]:
            self.ips[ip_src]["sports"] = {}
        if "sports" not in self.ips[ip_dst]:
            self.ips[ip_dst]["sports"] = {}

        if "dports" not in self.ips[ip_dst]:
            self.ips[ip_dst]["dports"] = {}
        if "dports" not in self.ips[ip_src]:
            self.ips[ip_src]["dports"] = {}

        if sport not in self.ips[ip_src]["sports"]:
            self.ips[ip_src]["sports"][sport] = 0
        if dport not in self.ips[ip_dst]["sports"]:
            self.ips[ip_dst]["sports"][dport] = 0

        if sport not in self.ips[ip_dst]["dports"]:
            self.ips[ip_dst]["dports"][sport] = 0
        if dport not in self.ips[ip_src]["dports"]:
            self.ips[ip_src]["dports"][dport] = 0

    def getPktCount(self, ip):
        cnt = 0
        for sport in self.ips[ip]["sports"]:
            cnt += self.ips[ip]["sports"][sport]
        return cnt

    def get_l_4(self, pkt):
        if self.protocol == "UDP":
            return UDP
        if self.protocol == "TCP":
            return TCP

        l_four_prot = ''
        if UDP in pkt:
            l_four_prot = UDP
        if TCP in pkt:
            l_four_prot = TCP

        return l_four_prot

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
            l_four_prot = self.get_l_4(pkt)
            sport = pkt[l_four_prot].sport
            dport = pkt[l_four_prot].dport

            if sport == self.port or dport == self.port:
                self.initIPDict(ip_src, ip_dst)
                self.initPortDict(ip_src, ip_dst, sport, dport)

                self.ips[ip_src]["sports"][sport] += 1
                self.ips[ip_src]["dports"][dport] += 1

                self.ips[ip_dst]["sports"][dport] += 1
                self.ips[ip_dst]["dports"][sport] += 1

            self.print_ips()

    def sniff(self):
        sniff(filter=self.protocol, prn=self.print_summary)


def main():
    args = get_cli_args()
    protocol = args.protocol.upper()
    port = int(args.port)
    s = Sniffer(protocol, port)
    s.sniff()


main()
