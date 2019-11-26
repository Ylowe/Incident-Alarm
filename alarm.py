#!/usr/bin/python3

from scapy.all import *
import pcapy
import argparse
import ipaddress
import re
import codecs
import base64

count = 0
username = ""
def packetcallback(packet):
  try:
    global count
    global username
    #if packet[TCP].dport == 80:
      #print("HTTP (web) traffic detected!")
    #Check TCP Flag header for FIN/NULL/XMAS Scan indiators
    if packet[TCP].flags == "F" + "P" + "U":
        print("ALERT #" + str(count) + ": XMAS scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1

    if packet[TCP].flags == 0:
        print("ALERT #" + str(count) + ": NULL scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1
    
    if packet[TCP].flags == "F":
        print("ALERT #" + str(count) + ": FIN scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1  

    #Check for Russians
    block1 = ('5.136.0.1','5.143.255.254')
    block2 = ('95.24.0.1','95.31.255.254')
    block3 = ('176.208.0.1','176.215.255.254')
    block4 = ('178.64.0.1','178.71.255.254')
    if(check_ip_range(packet[IP].src, *block1)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1

    if(check_ip_range(packet[IP].src, *block2)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1

    if(check_ip_range(packet[IP].src, *block3)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1

    if(check_ip_range(packet[IP].src, *block4)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1
    
    #Check for Lizards
    fb1 = ('66.220.144.0','66.220.159.255')
    fb2 = ('69.63.176.0','69.63.191.255')
    fb3 = ('204.15.20.0','204.15.23.255')
    if(check_ip_range(packet[IP].src, *fb1)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1
    
    if(check_ip_range(packet[IP].src, *fb2)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1
    
    if(check_ip_range(packet[IP].src, *fb2)):
        print("ALERT #" + str(count) + ": Incidnet #"+ count + "is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count +=1

    data = str(packet[Raw].load)
    
    if "Nikto" in data:
        print("ALERT #" + str(count) + ": Nikto scan is detected from " + str(packet[IP].src) + "(" + str(packet[TCP].dport) + "!)")
        count += 1

    if "Authorization: Basic" in data: 
        r = re.compile("Authorization: Basic (.*)")
        b64 = re.search(r, data).group(1)   
        re.sub('[^A-Za-z0-9]+','',b64)
        #clean up string 
        b64 = b64.replace("\\r\\n","")
        b64 = b64[:-1]
        b64_decode = str(base64.b64decode(b64))
        #print("b64 decode is: " + b64_decode)
        decodeli = list(b64_decode.split(":"))
        #print(decodeli)
        usernameauth = str(decodeli[0][2:])
        passwordauth = str(decodeli[1][:-1])
        print("ALERT #" + str(count) + ": Usernames and passwords sent in-the-clear (" + str(packet[TCP].dport) + ")" + " (username: " + usernameauth + ", password" + passwordauth + ")") 
        count +=1


    if "USER" in data:
        usernameli = list(data.split(" "))
        username = str(usernameli[1]).replace("\\r\\n", "")
        re.sub('[^A-Za-z0-9]+','',username)
        username = username[:-1]

    if "PASS" in data:
        passli = list(data.split(" "))
        password = passli[1].replace("\\r\\n", "")
        password = password[:-1]
        print("ALERT #" + str(count) + ": Usernames and passwords sent in-the-clear (" + str(packet[TCP].dport) + ")" + " (username: " + username + ", password" + password + ")") 
        count +=1
        

    
  except:
    pass


def convert_ipv4_tuple(ip):
    return tuple(int(n) for n in ip.split('.'))

def check_ip_range(ip, start, end):
    return convert_ipv4_tuple(start) < convert_ipv4_tuple(ip) < convert_ipv4_tuple(end)

parser = argparse.ArgumentParser(description='A network sniffer that identifies basic vulnerabilities')
parser.add_argument('-i', dest='interface', help='Network interface to sniff on', default='eth0')
parser.add_argument('-r', dest='pcapfile', help='A PCAP file to read')
args = parser.parse_args()

if args.pcapfile:
  try:
    print("Reading PCAP file %(filename)s..." % {"filename" : args.pcapfile})
    sniff(offline=args.pcapfile, prn=packetcallback)    
  except:
    print("Sorry, something went wrong reading PCAP file %(filename)s!" % {"filename" : args.pcapfile})
else:
  print("Sniffing on %(interface)s... " % {"interface" : args.interface})
  try:
    sniff(iface=args.interface, prn=packetcallback)
  except pcapy.PcapError:
    print("Sorry, error opening network interface %(interface)s. It does not exist." % {"interface" : args.interface})
  except:
    print("Sorry, can\'t read network traffic. Are you root?")
