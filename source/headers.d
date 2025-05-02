module headers;
import system;
import std.stdio;
import std.stdint;

/**
                           1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    0 |                          Magic Number                         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    4 |          Major Version        |         Minor Version         |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                           Reserved1                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                           Reserved2                           |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 |                            SnapLen                            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   20 | FCS |f|0 0 0 0 0 0 0 0 0 0 0 0|         LinkType              |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
**/

struct FILE_HEADER
{
  uint32_t magic;
  uint16_t major;
  uint16_t minor;
  /*
    * reserved1
    * reserved2
    */
  uint32_t snapLen;
  uint16_t linkType;
}

enum FILE_HEADER_LENGTH = 24; // the file header for pcap is 24 octets/bytes
enum FILE_HEADER_OFFSETS
{
  MAGIC = 0,
  MAJOR_MINOR = 4,
  SNAP_LEN = 16,
  LINK_TYPE = 20
}

enum BYTE_OFFSET = 4;

FILE_HEADER getFileHeader(ref File f, ENDIAN e)
{
  ubyte[FILE_HEADER_LENGTH] header;
  f.rawRead(header);

  FILE_HEADER fh;
  fh.magic = convert_u32(header[FILE_HEADER_OFFSETS.MAGIC .. $], e);
  fh.major = convert_u16(header[FILE_HEADER_OFFSETS.MAJOR_MINOR .. $][0 .. 2], e);
  fh.minor = convert_u16(header[FILE_HEADER_OFFSETS.MAJOR_MINOR .. $][2 .. $], e);
  fh.snapLen = convert_u32(header[FILE_HEADER_OFFSETS.SNAP_LEN .. $], e);
  fh.linkType = convert_u16(header[FILE_HEADER_OFFSETS.LINK_TYPE .. $], e);

  return fh;

}

/*
                          1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    0 |                      Timestamp (Seconds)                      |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    4 |            Timestamp (Microseconds or nanoseconds)            |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    8 |                    Captured Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   12 |                    Original Packet Length                     |
      +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   16 /                                                               /
      /                          Packet Data                          /
      /                        variable length                        /
      /                                                               /
      +---------------------------------------------------------------+
*/

struct PACKET_HEADER
{
  uint32_t seconds;
  uint32_t micro_nano;
  uint32_t capturedLength;
  uint32_t originalLength;
}

enum PACKET_HEADER_LENGTH = 16;

enum PACKET_HEADER_OFFSETS
{
  SECONDS = 0,
  MICRO_NANO = 4,
  CAP_LEN = 8,
  OG_LEN = 12
}

PACKET_HEADER getPacketHeader(ref File f, ENDIAN e)
{
  ubyte[PACKET_HEADER_LENGTH] header;
  f.rawRead(header);
  PACKET_HEADER ph;
  ph.seconds = convert_u32(header[PACKET_HEADER_OFFSETS.SECONDS .. $], e);
  ph.micro_nano = convert_u32(header[PACKET_HEADER_OFFSETS.MICRO_NANO .. $], e);
  ph.capturedLength = convert_u32(header[PACKET_HEADER_OFFSETS.CAP_LEN .. $], e);
  ph.originalLength = convert_u32(header[PACKET_HEADER_OFFSETS.OG_LEN .. $], e);
  return ph;
}

struct PACKET_DATA
{
  size_t index;
  PACKET_HEADER header;
  ubyte[] data;
}

PACKET_DATA getPacketData(ref File f, ENDIAN e, ref PACKET_HEADER ph)
{
  PACKET_DATA pd;
  pd.header = ph;
  pd.data = new ubyte[](ph.capturedLength);
  f.rawRead(pd.data);

  return pd;
}

