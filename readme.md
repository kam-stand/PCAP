# PCAP FILE PARSER

PCAP_CMD is a library as well as a command line tool to parse and analyze pcap file

## Overview

1. read in a pcap file and provide a interface analyzing network packets similar to wireshark but on the command line
2. anaylze and search for specific attributes with in each packet
3. support multiple [link types](http://www.tcpdump.org/linktypes.html)


## Sources

[Ethernet Frames](https://en.wikipedia.org/wiki/Ethernet_frame)


[What is a pcap file?](https://www.netresec.com/?page=Blog&month=2022-10&post=What-is-a-PCAP-file)

[File format specfification](https://www.ietf.org/archive/id/draft-gharris-opsawg-pcap-01.html)

## Requirements

1. official [D language compiler](https://dlang.org/download.html)
2. linux computer to build the executable

## Installation

```sh
 git clone https://github.com/kam-stand/PCAP.git

 cd PCAP_CMD

 ./run.sh

 ./bin/pcap <path/to/pcap/file>

```