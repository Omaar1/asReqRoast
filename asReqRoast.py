import argparse
from os import geteuid, devnull
from collections import OrderedDict

from scapy.all import *
conf.verb=0


#Console colors
W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan

DN = open(devnull, 'w')

pkt_frag_loads = OrderedDict()
challenge_acks = OrderedDict()
mail_auths = OrderedDict()
telnet_stream = OrderedDict()



def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-f", "--filterip", help="Do not sniff packets from this IP address; -f 192.168.0.4")
   return parser.parse_args()



def frag_remover(ack, load):
    '''
    Keep the FILO OrderedDict of frag loads from getting too large
    3 points of limit:
        Number of ip_ports < 50
        Number of acks per ip:port < 25
        Number of chars in load < 5000
    '''
    global pkt_frag_loads

    # Keep the number of IP:port mappings below 50
    # last=False pops the oldest item rather than the latest
    while len(pkt_frag_loads) > 50:
        pkt_frag_loads.popitem(last=False)

    # Loop through a deep copy dict but modify the original dict
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        if len(copy_pkt_frag_loads[ip_port]) > 0:
            # Keep 25 ack:load's per ip:port
            while len(copy_pkt_frag_loads[ip_port]) > 25:
                pkt_frag_loads[ip_port].popitem(last=False)

    # Recopy the new dict to prevent KeyErrors for modifying dict in loop
    copy_pkt_frag_loads = copy.deepcopy(pkt_frag_loads)
    for ip_port in copy_pkt_frag_loads:
        # Keep the load less than 75,000 chars
        for ack in copy_pkt_frag_loads[ip_port]:
            # If load > 5000 chars, just keep the last 200 chars
            if len(copy_pkt_frag_loads[ip_port][ack]) > 5000:
                pkt_frag_loads[ip_port][ack] = pkt_frag_loads[ip_port][ack][-200:]

def frag_joiner(ack, src_ip_port, load):
    '''
    Keep a store of previous fragments in an OrderedDict named pkt_frag_loads
    '''
    for ip_port in pkt_frag_loads:
        if src_ip_port == ip_port:
            if ack in pkt_frag_loads[src_ip_port]:
                # Make pkt_frag_loads[src_ip_port][ack] = full load
                old_load = pkt_frag_loads[src_ip_port][ack]
                concat_load = old_load + load
                return OrderedDict([(ack, concat_load)])

    return OrderedDict([(ack, load)])





def printer(src_ip_port, dst_ip_port, msg):
    if dst_ip_port != None:
        print_str = '[%s > %s] %s%s%s' % (src_ip_port, dst_ip_port, T, msg, W)
        # All credentials will have dst_ip_port, URLs will not


        # Escape colors like whatweb has
        ansi_escape = re.compile(r'\x1b[^m]*m')
        print_str = ansi_escape.sub('', print_str)

        # Log the creds
        logging.info(print_str)
    else:
        print_str = '[%s] %s' % (src_ip_port.split(':')[0], msg)
        print(print_str)





def ParseMSKerbv5TCP(Data):
    '''
    Taken from Pcredz because I didn't want to spend the time doing this myself
    I should probably figure this out on my own but hey, time isn't free, why reinvent the wheel?
    Maybe replace this eventually with the kerberos python lib
    Parses Kerberosv5 hashes from packets
    '''
    try:
        MsgType = Data[21:22]
        EncType = Data[43:44]
        MessageType = Data[32:33]
    except IndexError:
        print("kerberos ??? not sure ")
    print("\n\n\n*********text data ************\n\n\n")
    print(Data)
    print("\n\n\n\n*********hex data ************\n\n\n")
    # print("b'" + ''.join('\\x{:02x}'.format(x) for x in Data) + "'")
    # print("\n\n\n********* end data ************\n\n\n")
    print('message type in ascii: ',MsgType)
    # print("b'" + ''.join('\\x{:02x}'.format(x) for x in MsgType) + "'")
    print("\n\n\n********* end msg type !! ************\n\n\n")

    # print('encryption type : ',EncType)
    # print('message type again : ',MessageType)
'''
    if MsgType == "\x0a" and EncType == "\x17" and MessageType =="\x02":
        if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
            HashLen = struct.unpack('<b',Data[50:51])[0]
            if HashLen == 54:
                Hash = Data[53:105]
                SwitchHash = Hash[16:]+Hash[0:16]
                NameLen = struct.unpack('<b',Data[153:154])[0]
                Name = Data[154:154+NameLen]
                DomainLen = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
                Domain = Data[154+NameLen+4:154+NameLen+4+DomainLen]
                BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
                return 'MS Kerberos: %s' % BuildHash

        if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
            HashLen = struct.unpack('<b',Data[47:48])[0]
            Hash = Data[48:48+HashLen]
            SwitchHash = Hash[16:]+Hash[0:16]
            NameLen = struct.unpack('<b',Data[HashLen+96:HashLen+96+1])[0]
            Name = Data[HashLen+97:HashLen+97+NameLen]
            DomainLen = struct.unpack('<b',Data[HashLen+97+NameLen+3:HashLen+97+NameLen+4])[0]
            Domain = Data[HashLen+97+NameLen+4:HashLen+97+NameLen+4+DomainLen]
            BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
            return 'MS Kerberos: %s' % BuildHash

        else:
            Hash = Data[48:100]
            SwitchHash = Hash[16:]+Hash[0:16]
            NameLen = struct.unpack('<b',Data[148:149])[0]
            Name = Data[149:149+NameLen]
            DomainLen = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
            Domain = Data[149+NameLen+4:149+NameLen+4+DomainLen]
            BuildHash = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
            return 'MS Kerberos: %s' % BuildHash
'''




def pkt_parser(pkt):
    '''
    Start parsing packets here
    '''
    global pkt_frag_loads, mail_auths

    if pkt.haslayer(Raw):
        load = pkt[Raw].load

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        print("Ether")
        return

    # UDP
    if pkt.haslayer(UDP) and pkt.haslayer(IP):
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)
        print("UDP from : " , src_ip_port," to: ",dst_ip_port)
        return

    elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
        ack = str(pkt[TCP].ack)
        seq = str(pkt[TCP].seq)
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
        frag_remover(ack, load)
        pkt_frag_loads[src_ip_port] = frag_joiner(ack, src_ip_port, load)
        full_load = pkt_frag_loads[src_ip_port][ack]


    elif pkt.haslayer(TCP) and pkt.haslayer(Raw) and pkt.haslayer(IP):
        src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
        dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)

    # Kerberos over TCP
    decoded = Decode_Ip_Packet(str(pkt)[14:])
    kerb_hash = ParseMSKerbv5TCP(decoded['data'][20:])
    if kerb_hash:
        printer(src_ip_port, dst_ip_port, kerb_hash)





def Decode_Ip_Packet(s):
    '''
    Taken from PCredz, solely to get Kerb parsing
    working until I have time to analyze Kerb pkts
    and figure out a simpler way
    Maybe use kerberos python lib
    '''
    d={}
    d['header_len']=ord(s[0]) & 0x0f
    d['data']=s[4*d['header_len']:]
    return d


def main(args):

    if args.pcap:
        try:
            pass
            # for pkt in PcapReader(args.pcap):
            #     pkt_parser(pkt)
        except IOError:
            exit('[-] Could not open %s' % args.pcap)

    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')

    if args.interface:
        conf.iface = args.interface
        print('[*] Using interface:  ', conf.iface)
        # sniff(iface=conf.iface, prn=lambda x: x.summary(), store=0)
        sniff(iface=conf.iface, prn=pkt_parser, store=0)




if __name__ == "__main__":
   main(parse_args())









