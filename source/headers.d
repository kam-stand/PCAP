module headers;
import system;

import core.stdc.stdio;
import core.stdc.stdint;
import core.stdc.stdlib;



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
  MAJOR = 4,
  MINOR = 6,
  SNAP_LEN = 16,
  LINK_TYPE = 20
}

enum BYTE_OFFSET = 4;



FILE_HEADER get_file_header(FILE *f, ENDIAN e) @nogc
{
  ubyte[FILE_HEADER_LENGTH] buffer;
  fread(buffer.ptr, 1, FILE_HEADER_LENGTH, f);
  FILE_HEADER file_header;
  file_header.magic = convert_u32(buffer[FILE_HEADER_OFFSETS.MAGIC..FILE_HEADER_OFFSETS.MAGIC+BYTE_OFFSET], e);
  file_header.major = convert_u16(buffer[FILE_HEADER_OFFSETS.MAJOR..FILE_HEADER_OFFSETS.MAJOR+BYTE_OFFSET/2], e);
  file_header.minor = convert_u16(buffer[FILE_HEADER_OFFSETS.MINOR..FILE_HEADER_OFFSETS.MINOR+BYTE_OFFSET/2], e);
  file_header.snapLen = convert_u32(buffer[FILE_HEADER_OFFSETS.SNAP_LEN..FILE_HEADER_OFFSETS.SNAP_LEN+BYTE_OFFSET], e);
  file_header.linkType = convert_u16(buffer[FILE_HEADER_OFFSETS.LINK_TYPE..FILE_HEADER_OFFSETS.LINK_TYPE+BYTE_OFFSET/2],e);
  return file_header;
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


struct PACKET_DATA
{
  size_t index;
  PACKET_HEADER header;
  ubyte* data;
}






