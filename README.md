# AsReqRoast

AsReqRoast is a simple tool for extracting As-Req hashes from kerberos packets. Below is a brief overview of what this tool does.




## Usage

**-p** specify a pcap file to use
```
python3 asReqRoast.py -p <file.pcap>
```

  
__-i__ specify an interface for sniffing

```
python3 asReqRoast.py -i <interface>
```

__-o__ specify a file to store hashes

```
python3 asReqRoast.py -i <interface> -o out.txt
```
