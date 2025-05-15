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

ETHERNET_HEADER getEthernetHeader(PACKET_DATA *pd, ENDIAN e) @nogc
{
  
  ETHERNET_HEADER eh;
  ubyte[] header = pd.data[0 .. MAC_HEADER];
  eh.dest = header[MAC_HEADER_OFFSETS.DEST .. MAC_HEADER_OFFSETS.SOURCE];
  eh.source = header[MAC_HEADER_OFFSETS.SOURCE .. MAC_HEADER_OFFSETS.LENGTH];
  eh.length_type = header[MAC_HEADER_OFFSETS.LENGTH .. $];
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
