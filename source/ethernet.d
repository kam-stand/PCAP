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
  ARP = 0x0806,
  IPX = 0x8137,
  IPV6 = 0x86dd
}

enum IPV4_HEADER_LENGTH = 20; // minimum IP header length

enum IPV4_FIELD_OFFSETS
{
  Version = 0,
  IHL = 4,
  TOS = 8,
  TotalLength = 16,
  Identification = 32,
  FlagsFragOff = 48,
  TTL = 64,
  Protocol = 72,
  HeaderChecksum = 80,
  SourceAddr = 96,
  DestAddr = 128
}

enum IPV4_FIELD_LENGTHS
{
  Version = 4,
  IHL = 4,
  TOS = 8,
  TotalLength = 16,
  Identification = 16,
  FlagsFragOff = 16,
  TTL = 8,
  Protocol = 8,
  HeaderChecksum = 16,
  SourceAddr = 32,
  DestAddr = 32
}

/** 
 * Each header field in the tcp has a specific length and offset
 */

struct IPV4_PACKET
{
  ubyte[IPV4_FIELD_LENGTHS.Version] ver;
  ubyte[IPV4_FIELD_LENGTHS.IHL] ihl;
  ubyte[IPV4_FIELD_LENGTHS.TOS] tos;
  ubyte[IPV4_FIELD_LENGTHS.TotalLength] totallength;
  ubyte[IPV4_FIELD_LENGTHS.Identification] identification;
  ubyte[IPV4_FIELD_LENGTHS.FlagsFragOff] flagsfragoff;
  ubyte[IPV4_FIELD_LENGTHS.TTL] ttl;
  ubyte[IPV4_FIELD_LENGTHS.Protocol] protocol;
  ubyte[IPV4_FIELD_LENGTHS.HeaderChecksum] headerchecksum;
  ubyte[IPV4_FIELD_LENGTHS.SourceAddr] sourceaddr;
  ubyte[IPV4_FIELD_LENGTHS.DestAddr] destaddr;
  ubyte[] data;

}

IPV4_PACKET getIPV4Packets(ref PACKET_DATA pd)
{
  IPV4_PACKET ip;

  ubyte[IPV4_HEADER_LENGTH] header;
  header = pd.data[MAC_HEADER .. MAC_HEADER + IPV4_HEADER_LENGTH];
  writefln("Size of ipv4 packet %d", header.length);
  return ip;

}
