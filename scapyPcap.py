from scapy.all import *




W = '\033[0m'  # white (normal)
T = '\033[93m'  # tan


import  binascii


'''
      des-cbc-crc                        1             6.2.3
      des-cbc-md4                        2             6.2.2
      des-cbc-md5                        3             6.2.1
      [reserved]                         4
      des3-cbc-md5                       5
      [reserved]                         6
      des3-cbc-sha1                      7
      dsaWithSHA1-CmsOID                 9           (pkinit)
      md5WithRSAEncryption-CmsOID       10           (pkinit)
      sha1WithRSAEncryption-CmsOID      11           (pkinit)
      rc2CBC-EnvOID                     12           (pkinit)
      rsaEncryption-EnvOID              13   (pkinit from PKCS#1 v1.5)
      rsaES-OAEP-ENV-OID                14   (pkinit from PKCS#1 v2.0)
      des-ede3-cbc-Env-OID              15           (pkinit)
      des3-cbc-sha1-kd                  16              6.3
      aes128-cts-hmac-sha1-96           17          [KRB5-AES]
      aes256-cts-hmac-sha1-96           18          [KRB5-AES]
      rc4-hmac                          23          (Microsoft)
      rc4-hmac-exp                      24          (Microsoft)
      subkey-keymaterial                65     (opaque; PacketCable)
'''


### kerberos  ports  ... 88/UDP
### pvno: 5                            --> load[12]x2 = [24,26] = 05
### msg-type: krb-as-req (10)          --> load[17]x2 = [34,36] = 0a
### etype: eTYPE-ARCFOUR-HMAC-MD5 (23) --> load[39]x2 = [78,80] = 17
### padata-type: pA-ENC-TIMESTAMP (2)  --> load[28]x2 = [56,58] = 02
'''
padata-type: pA-ENC-TIMESTAMP (2)
    padata-value: 303da003020117a236043471319a93d60531fcb443f7e96039f540addbe67ccf9dd3c3da…
        etype: eTYPE-ARCFOUR-HMAC-MD5 (23)
        cipher: 71319a93d60531fcb443f7e96039f540addbe67ccf9dd3c3da9e233612816c5720447ae2…
'''
### kerberos TCP before preAuth no hash exist
### TCP before Pre-auth
### start with  6a 81
### pvno: 5                            --> [20,22] = 05
### msg-type: krb-as-req (10)          --> [30,32] = 0a
### etype: eTYPE-ARCFOUR-HMAC-MD5 (23) --> notExist
### padata-type: pA-ENC-TIMESTAMP (2)  --> notExist

'''
### kerberos TCP after preAuth message
### start with  6a 82 xx xx 30 82
### pvno: 5                            --> [20,22] = 05
### msg-type: krb-as-req (10)          --> [30,32] = 0a
### etype: eTYPE-ARCFOUR-HMAC-MD5 (23) --> notExist
### padata-type: pA-ENC-TIMESTAMP (2)  --> notExist
'''


###PA-DATA pA-PAC-REQUEST  30 11 a1 04 02 02 00 80 a2 09 04073005a0030101ff


protocols =	{6:'tcp',
		17:'udp',
		1:'icmp',
		2:'igmp',
		3:'ggp',
		4:'ipcap',
		5:'ipstream',
		8:'egp',
		9:'igrp',
		29:'ipv6oipv4',
		}

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

def printer(proto,srcIP,dstIP,src_ip_port, dst_ip_port, size ,msg):
    # if dst_ip_port != None:
    print_str = '[%s][%s : %s > %s : %s] %s' % (proto,src_ip,src_ip_port,dst_ip, dst_ip_port, msg )

        # # Escape colors like whatweb has
        # ansi_escape = re.compile(r'\x1b[^m]*m')
        # print_str = ansi_escape.sub('', print_str)

    # else:
    #     print_str = '[%s] %s' % (src_ip_port.split(':')[0], msg)
    print(print_str)
#
# packets = rdpcap('krb-816.cap')
# pkList=[0,2,18,22]


packets = rdpcap('asReQ.pcap')
pkList=[15,117]


# packets = rdpcap('host-and-user-ID-pcap-06.pcap')
# pkList=[30,130,348,429]

proto = ""
sport = ""
dport = ""

for mypkt in pkList:
    pkt=packets[mypkt]
    pktSize=pkt.sprintf("%IP.len%")
    # print(pkt.haslayer(TCP))
    src_ip=pkt[IP].src
    dst_ip=pkt[IP].dst
    # print(pkt[IP].proto)

    if TCP in pkt:
        proto = "TCP"
        sport=pkt[TCP].sport
        dport=pkt[TCP].dport
        # print("TCP "+str(sport)+str(dport))
    elif UDP in pkt:
        proto = "UDP"
        sport=pkt[UDP].sport
        dport=pkt[UDP].dport
    # print("TCP "+str(sport)+str(dport))
    # printer(proto,src_ip,dst_ip,sport,dport,pktSize,"tesssssst")



hashes = []
for i in pkList:
    hpayload = packets[i][Raw].load.hex()
    # payload = packets[i][Raw].load
    hpayload = hpayload[8:]     ##should start with 6a 82
    #print(hpayload)             ## start with 30
    pData_Header=hpayload[44:]
    hash = pData_Header[44:pData_Header.index("3011a10402")]  ##untill the start of PAC header
    hashes.append(hash)
    # print(pData_Header)
    print("cipher detected :  "+hash)
    pvno = hpayload[24:26]          ##05
    MsgType = hpayload[34:36]       ##0a
    EncType = hpayload[78:80]       ##17
    pdataType = hpayload[56:58]     ##02  encrypted timestamp message
    # print(pData_Header.index("3011a10402"))

    ## convert hex to decimal
    pvno_d = int(pvno, 16)
    MsgType_d = int(MsgType, 16)
    pdataType_d = int(pdataType, 16)
    EncType_d = int(EncType, 16)

    print(" packet NO :"+str(i)+" pvno  : [\\x"+pvno+"] - "+str(pvno_d))
    print(" packet NO :"+str(i)+" message type : [\\x"+MsgType+"] - "+str(MsgType_d))
    print(" packet NO :"+str(i)+" enc type : [\\x"+EncType+"] - "+encTypes[str(EncType_d)])
    print(" packet NO :"+str(i)+" pdata type_2 : [\\x"+pdataType+"] - "+str(pdataType_d))







# c=0
# hpayload = packets[0][Raw].load.hex()
# for i in range(len(hpayload)+1):
#     print(str(i) +" : "+str(hpayload[c])+hpayload[c+1])
#     i=i+1
#     c=c+2

# print(payload)


