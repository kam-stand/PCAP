module ethernet;
import headers;
import system;
import core.stdc.stdio;
import core.stdc.stdint;
import core.stdc.string;
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

void get_ethernet_header(PACKET_DATA *pd)  @nogc
{
    // pd->data must have at least 14 bytes
  if (pd is null || pd.data is null)
    return;

  // Copy bytes safely
  memcpy(pd.ethernet_header.dest.ptr,   pd.data + MAC_HEADER_OFFSETS.DEST,   6);
  memcpy(pd.ethernet_header.source.ptr, pd.data + MAC_HEADER_OFFSETS.SOURCE, 6);
  memcpy(pd.ethernet_header.length_type.ptr, pd.data + MAC_HEADER_OFFSETS.LENGTH, 2);


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
  IPV6 = 0x86dd,
  INVALID
}


ETHERNET_FRAME determine_ethernet_frame(ETHERNET_HEADER ethernet_header)
{

 ushort ether_type = (cast(ushort)ethernet_header.length_type[0] << 8) |
                        ethernet_header.length_type[1];
  if (ether_type >= ETHERNET_FRAME.ETHERNET_II)
  {
    return ETHERNET_FRAME.ETHERNET_II;
  }

  else if (ether_type < ETHERNET_FRAME.IEEE_802_3)
  {
    return ETHERNET_FRAME.IEEE_802_3;
  }

  return ETHERNET_FRAME.INVALID;
}

DATAGRAM_TYPE determine_datagram_type(ETHERNET_HEADER header)
{
  ETHERNET_FRAME ethernet_frame = determine_ethernet_frame(header);
  if (ethernet_frame == ETHERNET_FRAME.IEEE_802_3)
  {
    return DATAGRAM_TYPE.INVALID;
  }

    ushort ethertype = (cast(ushort)header.length_type[0] << 8) |
                       header.length_type[1];

    switch (ethertype)
    {
        case DATAGRAM_TYPE.IPV4:
            return DATAGRAM_TYPE.IPV4;
        case DATAGRAM_TYPE.ARP:
            return DATAGRAM_TYPE.ARP;
        case DATAGRAM_TYPE.IPX:
            return DATAGRAM_TYPE.IPX;
        case DATAGRAM_TYPE.IPV6:
            return DATAGRAM_TYPE.IPV6;
        default:
            return DATAGRAM_TYPE.INVALID; 
    }

    return DATAGRAM_TYPE.INVALID;
}