import os
import time

from scapy.all import sniff, IP, TCP
import datetime
import requests
import json
import subprocess
import mysql.connector
import ipaddress
import csv

abuseIpdbApi = "<YOUR IPABUSEDB KEY HERE>"
abuseIpdbCat = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
    0: "N/A"  # CUSTOM
}


def createFwLogsFile():
    if not os.path.exists('fwLogs.csv'):
        column_names = ['Time Stamp', 'Destination IP', 'Destination Port', 'Source IP', 'Abuse Score', 'Country',
                        'Categories', 'About', 'Action Type']
        with open('fwLogs.csv', 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(column_names)
    else:
        pass


def MySqlConn():
    sName = '127.0.0.1'
    uName = 'root'
    passw = 'password'
    db_name = 'asicwall'

    conn = mysql.connector.connect(
        host=sName,
        user=uName,
        password=passw,
        database=db_name
    )

    return conn


allIPs = {}


def is_private(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private
    except ValueError:
        return False


def checkMalIP(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": f"{abuseIpdbApi}",
        "Accept": "application/json"
    }
    params = {
        "ipAddress": f"{str(ip)}",
        "maxAgeInDays": 60,
        "verbose": True
    }
    try:
        response = (requests.get(url, headers=headers, params=params).json())
    except:
        cprint("API call to AbuseIPDB Failed!")

    categoryList = []
    try:
        abuseScore = response['data']['abuseConfidenceScore']
    except:
        abuseScore = int(0)
    try:
        country = response['data']['countryName']
    except:
        country = "N/A"
    try:
        domain = response['data']['domain']
    except:
        domain = "N/A"
    try:
        categories = response['data']['reports'][0]['categories']
    except:
        categories = 0

    if isinstance(categories, list):
        for i in categories:
            categoryList.append(abuseIpdbCat.get(int(i)))
    else:
        categoryList.append(abuseIpdbCat.get(int(categories)))

    return {'ip': ip, 'score': abuseScore, 'domain': domain, 'country': country, 'categories': ", ".join(categoryList)}


def cprint(message):
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    content = f" [+] {str(current_time)} -> {str(message)} \n"
    print(content)
    file = open("logs.txt", 'a')
    file.write(content)
    file.close()


def connectLogs(src_IP, dst_IP, dst_Port, actionType):
    createFwLogsFile()

    with open('fwLogs.csv', 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)

        conn = MySqlConn()
        cursor = conn.cursor(dictionary=True)

        qry = "SELECT * FROM ipaddresses WHERE IP = %s"
        qryParams = (src_IP,)
        cursor.execute(qry, qryParams)
        res = cursor.fetchone()

        try:
            score = res['score']
        except:
            score = "N/A"
        try:
            country = res['country']
        except:
            country = "N/A"
        try:
            categories = res['categories']
        except:
            categories = "N/A"
        try:
            about = res['about']
        except:
            about = "N/A"

        current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        writer.writerow([str(current_time), dst_IP, dst_Port, src_IP, score, country, categories, about, actionType])


def is_blocked(ip):
    conn = MySqlConn()
    cursor = conn.cursor(dictionary=True)

    qry = "SELECT * FROM ipaddresses WHERE IP = %s AND is_blocked = %s"
    qryParams = (ip, 1)
    cursor.execute(qry, qryParams)
    res = cursor.fetchone()
    count = cursor.rowcount

    cursor.close()
    conn.close()

    if count > 0:
        return True
    else:
        return False


def writeToDB(ip, score, domain, country, categories, is_blocked):
    conn = MySqlConn()
    cursor = conn.cursor(dictionary=True)

    qry = "INSERT INTO ipaddresses (ip, score, domain, country, categories, is_blocked) VALUES (%s, %s, %s, %s, %s, %s)"
    values = (ip, score, domain, country, categories, is_blocked)

    cursor.execute(qry, values)
    conn.commit()

    cursor.close()
    conn.close()


def portsToSniff(pRange: list):
    # Doc: portsToSniff([80, 8080, [100,120]]). The whole argument should be list. Single ports should be written directly,
    # and range of ports should be defined in another list -> [80,100] to signify 80 - 100

    ports = []
    for i in pRange:
        if not isinstance(i, list):
            ports.append(str(i))
        else:
            for j in range(i[0], i[1]):
                ports.append(str(j))

    return ports


def getIPInfoDeDup(ip):
    if ip not in allIPs.keys():
        ipInfo = checkMalIP(ip)
        allIPs[ip] = {'ip': ip, 'score': ipInfo.get("score"), 'domain': ipInfo.get("domain"),
                      'country': ipInfo.get("country"), 'categories': ipInfo.get("categories")}
        return {'ip': ip, 'score': int(ipInfo.get("score")), 'domain': ipInfo.get("domain"),
                'country': ipInfo.get("domain"),
                'categories': ipInfo.get("categories")}

    if ip in allIPs.keys():
        ipInfo = allIPs.get(ip)
        return {'ip': ip, 'score': int(ipInfo.get("score")), 'domain': ipInfo.get("domain"),
                'country': ipInfo.get("domain"),
                'categories': ipInfo.get("categories")}


# This is the main filter to be modified for Application Specific Listening

def filter(ip, port):
    # Doc: portsToSniff([80, 8080, [100,120]]). The whole argument should be list. Single ports should be written directly,
    # and range of ports should be defined in another list -> [80,100] to signify 80 - 100

    listeningIP = "192.168.1.2"
    if str(ip) == listeningIP and str(port) in portsToSniff([8080, [40000, 40200]]):
        return True


# --- #


def action(packet):
    if IP and TCP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport

        if filter(dst_ip, dst_port):

            if is_blocked(src_ip) is True:
                cprint(
                    f"Custom Indicator: {src_ip} established connection and matched blocked inbound rule on {dst_ip}:{dst_port}! ")
                connectLogs(src_IP=src_ip, dst_IP=dst_ip, dst_Port=dst_port, actionType="Blocked")

            else:
                cprint(f"Non Blocked IP {src_ip} established connection on {dst_ip}:{dst_port}! ")
                connectLogs(src_IP=src_ip, dst_IP=dst_ip, dst_Port=dst_port, actionType="Allowed")

                if is_private(src_ip):
                    cprint(f"Private IP {src_ip} Not Blocking!")

                else:
                    info = getIPInfoDeDup(src_ip)
                    if int(info['score']) >= 15:
                        cprint(
                            f"Blocking IP {info['ip']} scored at {info['score']}% from {info['country']} under {info['categories']}!")
                        writeToDB(info['ip'], info["score"], info["domain"], info["country"], info["categories"], 1)
                        advProc = subprocess.Popen(
                            f'netsh advfirewall firewall add rule name=\"BlockIOC-{src_ip}\" dir=in action=block remoteip={src_ip}',
                            stdout=subprocess.PIPE)
                        cprint(f"WinADV Firewall Message: {advProc.stdout.read()}")
                    else:
                        cprint(
                            f"Not Blocking IP {info['ip']} scored at {info['score']}% from {info['country']} under {info['categories']} bellow threshold.")


def start_sniffing(interface):
    print(f"Starting packet sniffing on {interface}")
    sniff(iface=interface, prn=action, store=0)


def writeIOCs(path):
    with open(path) as csvfile:

        conn = MySqlConn()
        cursor = conn.cursor(dictionary=True)

        reader = csv.reader(csvfile)
        for row in reader:
            firstRow = row

            if firstRow[0].lower().strip() == "ioc" and firstRow[1].lower().strip() == 'about':
                csVerify = True
            else:
                csVerify = False
            break

        if csVerify is True:
            for row in reader:
                firstRow = row
                if firstRow[0].lower().strip() == "ioc" and firstRow[1].lower().strip() == 'about':
                    pass
                else:
                    ioc = row[0]
                    about = row[1]
                    cprint(f"Blocking IOC: {ioc} against {about} in Firewall! ")
                    advProc = subprocess.Popen(
                        f'netsh advfirewall firewall add rule name=\"BlockIOC-{ioc}\" dir=in action=block remoteip={ioc}',
                        stdout=subprocess.PIPE)
                    time.sleep(0.5)
                    cprint(f"WinADV Firewall Message: {advProc.stdout.read()}")
                    cprint(f"Writing to DB! ")
                    qry = "INSERT IGNORE INTO ipaddresses (ip, about, is_blocked) VALUES (%s, %s, %s)"
                    values = (ioc, about, 1)
                    cursor.execute(qry, values)
                    conn.commit()

            conn.commit()
            cursor.close()
            conn.close()

        if csVerify is False:
            print("Column Error. IOC and About column not found")



if __name__ == "__main__":
    choice = input("Do you wanna block some IOCs before sniffing activity? Y/N: ")
    if choice.lower() == "y":
        path = input("input Path of CSV. CSV file should have 2 columns! IOC, About! \n : " )
        writeIOCs(path)
        print()
        print("IOCs blocked. Restart script to start sniffing!")
    if choice.lower() == "n":
        network_interface = 'Ethernet'
        start_sniffing(network_interface)
    else:
        print("Not a Valid Choice!")
