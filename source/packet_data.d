module packet_data;
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


struct ETHERNET_HEADER
{
  uint8_t dest;
  uint8_t source;
  uint8_t length;
}


ETHERNET_HEADER getEthernetHeader(ref PACKET_DATA pd, ENDIAN e)
{
  ubyte[] macHeader = pd.data[0 .. MAC_HEADER];
  writeln(macHeader);
  each!(a => writef("%02x ", a))(macHeader);


  ETHERNET_HEADER eh;

  return eh;
}