module ethernet;
import headers;
import system;
import std.stdio;
import std.stdint;
import std.algorithm;

enum LINK_TYPE : uint16_t
{
  ETHERNET = 1,
  RAW_IP = 101,
  WIRELESS = 105,
  RAW_IPV4 = 228
}

enum MAC_HEADER = 14;

enum MAC_HEADER_OFFSETS
{
  DEST = 0,
  SOURCE = 6,
  LENGTH = 12
}

struct ETHERNET_HEADER
{
  ubyte[6] dest;
  ubyte[6] source;
  ubyte[2] length_type;
}

ETHERNET_HEADER getEthernetHeader(ref PACKET_DATA pd, ENDIAN e)
{
  writeln(pd);

  ETHERNET_HEADER eh;
  ubyte[] header = pd.data[0 .. MAC_HEADER];
  eh.dest = header[MAC_HEADER_OFFSETS.DEST .. MAC_HEADER_OFFSETS.SOURCE];
  eh.source = header[MAC_HEADER_OFFSETS.SOURCE .. MAC_HEADER_OFFSETS.LENGTH];
  eh.length_type = header[MAC_HEADER_OFFSETS.LENGTH .. $];
  writeln(eh);
  printIp(pd);
  return eh;
}

enum ETHERNET_FRAME
{
  ETHERNET_II = 1536,
  IEEE_802_3 = 1500, 
  INVALID
}


enum DATAGRAM_TYPE
{
  IPV4 = 0x0800,
  ARP =  0x0806,
  IPX =  0x8137,
  IPV6 = 0x86dd
}


void printIp(ref PACKET_DATA pd)
{
      ubyte[] ipDatagram = pd.data[MAC_HEADER .. $];
    writeln("IP Datagram Length: ", ipDatagram.length);
    writeln("IP Datagram (bytes): ", ipDatagram);

    if (ipDatagram.length < 20) {
        writeln("Error: IP datagram too short to contain a full header.");
        return;
    }

    ubyte[] header = ipDatagram[0 .. IPV4_HEADER_LENGTH];
    writeln("First 3 bytes of header: ", header[0 .. 3]); // Corrected slice

    // Extract Version and IHL from the first byte
    ubyte versionIhlByte = header[0];
    ubyte v1 = versionIhlByte >> 4; // Shift right by 4 bits to get the version
    ubyte ihl = versionIhlByte & 0x0F;    // Mask with 00001111 to get the IHL

    // Extract TOS (Type of Service) from the second byte
    ubyte tos = header[1];

    // Extract Total Length from the third and fourth bytes (big-endian)
    //ushort totalLength = to!(ushort)([header[2], header[3]]); // Combine bytes
    uint16_t totalLength = (header[2] + header[3]);
    writeln("IP Version: ", v1);
    writeln("IHL (Header Length in 32-bit words): ", ihl);
    writeln("Header Length (bytes): ", ihl * 4);
    writeln("TOS (Type of Service): ", tos);
    writeln("Total Length: ", totalLength);
}

enum IPV4_HEADER_LENGTH = 20; // minimum IP header length if there is an option fields we can append


struct IPV4
{
  
}