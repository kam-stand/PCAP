module pcap;
import std.stdio;
import std.stdint;
import std.conv;
import std.bitmanip;
import system;
import std.range;
import std.algorithm;

enum HEADER_LENGTH = 24; // header is 24 octets
enum MAJOR_MINOR_LENGTH = 2;
enum HEADER_CHUNKS // every 4 bytes represent a portion of the header
{
  MAGIC = 0,
  MAJOR_MINOR = 1,
  SNAP_LEN = 4,
  LINK_TYEP = 5
}


/****

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

***/

struct FileHeader
{
  uint32_t magicNumber;
  uint16_t majorVersion;
  uint16_t minorVersion;
  /**
        /* Reserved1 32 bits
        /* Reserved2 32 bits
        /*
        */
  uint32_t snapLen;
  uint16_t linkType;

  // Framce Cyclic sequence 4 bits

}

FileHeader getHeader(ref ubyte[] content, in ENDIAN e)
{
  FileHeader header;
  ubyte[] fileHeader = content[0 .. HEADER_LENGTH];
  auto c = chunks(fileHeader, MAGIC_HEADER);
  
  uint32_t snapLen = read_u32(c[4], e);
  ubyte [] major_minor = c[1];
  writeln(major_minor.length);
  uint16_t major = read_u16(major_minor[0 .. MAJOR_MINOR_LENGTH], e);
  uint16_t minor = read_u16(major_minor[MAJOR_MINOR_LENGTH .. $], e);
  uint32_t magic = read_u32(c[0], e);
  uint16_t linkType = read_u16(c[5], e);
  header.magicNumber = magic;
  header.linkType = linkType;
  header.snapLen = snapLen;
  header.minorVersion = minor;
  header.majorVersion = major;
  return header;
}
