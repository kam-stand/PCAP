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
enum PACKET_HEADER_LENGTH = 16;
enum HEADER_CHUNKS // every 4 bytes represent a portion of the header
{
  MAGIC = 0,
  MAJOR_MINOR = 1,
  SNAP_LEN = 4,
  LINK_TYPE = 5
}

enum PACKET_CHUNK
{
  SECODS = 0,
  NANO = 1,
  CAPTURED_LEN = 2,
  ORIGINAL_LEN = 3
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

struct PacketRecord
{
  uint32_t seconds;
  union  // determined by the magic number 
  {
    uint32_t nanoSeconds;
    uint32_t microSeconds;
  }
  uint32_t capturedPacketLenght; // size of the data length for packet record
  uint32_t originalPacketLength;
  ubyte *data;
  PacketRecord *next;
  
}

FileHeader getHeader(ref ubyte[] content, in ENDIAN e)
{
  ubyte[] fileHeader = content[0 .. HEADER_LENGTH];
  auto fileChunks = chunks(cast(ubyte[]) fileHeader, MAGIC_HEADER);
  uint32_t magic = read_u32(fileChunks[HEADER_CHUNKS.MAGIC], e);
  uint16_t major = read_u16(fileChunks[HEADER_CHUNKS.MAJOR_MINOR][0 .. MAJOR_MINOR_LENGTH], e);
  uint16_t minor = read_u16(fileChunks[HEADER_CHUNKS.MAJOR_MINOR][MAJOR_MINOR_LENGTH .. $], e);
  uint32_t snapLen = read_u32(fileChunks[HEADER_CHUNKS.SNAP_LEN], e);
  uint16_t linkType = read_u16(fileChunks[HEADER_CHUNKS.LINK_TYPE], e);
  FileHeader header = {magic, major, minor, snapLen, linkType};
  writefln("%02x", magic);
  return header;
}


PacketRecord getPackets(ref ubyte[] content, in ENDIAN e)
{
  PacketRecord p;
  ubyte[] packets = content[HEADER_LENGTH .. $];
  writeln(getPacketHeader(packets));
  return p;
}

ubyte[] getPacketHeader(ubyte [] slice)
{
  ubyte[] b;
  auto packetHeaderChunks = chunks(slice, MAGIC_HEADER);
  writeln(packetHeaderChunks[0]);
  writefln("%d ", read_u32(packetHeaderChunks[0], ENDIAN.Little));
  writefln("%d ", read_u32(packetHeaderChunks[1], ENDIAN.Little));
  writefln("%d", read_u32(packetHeaderChunks[2], ENDIAN.Little));
  writefln("%d", read_u32(packetHeaderChunks[3], ENDIAN.Little));
  return b;
}

