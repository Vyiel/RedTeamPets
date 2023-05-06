import sys
from scapy.all import *
import datetime
from win10toast import ToastNotifier
import csv
import ipaddress
from winotify import Notification


def timestamp():
    timestamp = datetime.datetime.now()
    formatted_timestamp = timestamp.strftime("%d-%m-%Y %H:%M:%S")
    return formatted_timestamp


def check_IP_list(ip_list):
    total_IPs = len(ip_list)
    counter = 0
    for i in ip_list:
        try:
            ipaddress.ip_address(i.strip())
            counter += 1
        except Exception as e:
            break

    if counter == total_IPs:
        return True
    else:
        return False


def proto_num_to_name(num):

    number = int(num)
    protocol_names = {
        1: "ICMP",
        2: "IGMP",
        41: "IPv6",
        58: "ICMPv6",
        89: "OSPF",
        132: "SCTP",

                    }

    try:
        val = protocol_names.get(number)
        return val
    except:
        return str(number)



def read_detection_list():
    try:
        with open("list.txt", 'r') as file:
            content = file.readlines()
        file.close()
    except FileNotFoundError:
        print()
        print("Place the line separated IP list within the same dir as list.txt")
        print()
        content = None

    if content is None:
        return None
    else:
        detect_list = content
        return detect_list


dlist = read_detection_list()
n_list = []

def act(packet):
    global src_port, dst_port, protocol, src_ip, dst_ip

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if packet.haslayer(TCP):
            protocol = "TCP"
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport

        elif packet.haslayer(UDP):
            protocol = "UDP"
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport

        else:
            protocol = proto_num_to_name(packet[IP].proto)
            src_port = 0
            dst_port = 0

    if dlist is not None and check_IP_list(dlist) is True:
        for i in dlist:
            if src_ip == i.strip() or dst_ip == i.strip():
                detection = [timestamp(), src_ip, str(src_port), dst_ip, str(dst_port), protocol]
                if detection not in n_list:
                    n_list.append(detection)
                    notify(protocol + ": " + str(src_ip) + "  ----->  " + str(dst_ip))
                else:
                    pass
    else:
        print("No valid IP address OR malformed IPs found in file. Please Re-Check")
        sys.exit()


toast = ToastNotifier()


def notify(body):
    toast = Notification(app_id="LilMon",
                         title="Network Communication Matched",
                         msg=body)

    toast.show()


def main():
    print()
    print("-----------------")
    print("""
    - The tool is a simple network monitor that sniffs all interfaces and checks IPs 
      from a text file in the same directory and notifies.
    - Keep the list.txt in the same directory file with IPs you want to detect on transaction separated by next line.
    - Once the program is quit, a log.csv with detection along with time will be created in the same directory.
    
    """)
    print("-----------------")
    print()

    try:
        sniff(prn=act, filter="ip")
        print("Press CTRL+C to stop sniffing and write to log")

    except KeyboardInterrupt:
        print("Interrupt received. Stopping program")

    finally:

        header = ["Timestamp", "Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol"]

        with open('log.csv', mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(header)
            for i in n_list:
                writer.writerow(i)


if __name__ == '__main__':
    main()
