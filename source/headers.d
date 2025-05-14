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

FILE_HEADER get_file_header(FILE* f, ENDIAN e) @nogc
{
  ubyte[FILE_HEADER_LENGTH] buffer;
  fread(buffer.ptr, 1, FILE_HEADER_LENGTH, f);
  FILE_HEADER file_header;
  file_header.magic = convert_u32(
    buffer[FILE_HEADER_OFFSETS.MAGIC .. FILE_HEADER_OFFSETS.MAGIC + BYTE_OFFSET], e);
  file_header.major = convert_u16(
    buffer[FILE_HEADER_OFFSETS.MAJOR .. FILE_HEADER_OFFSETS.MAJOR + BYTE_OFFSET / 2], e);
  file_header.minor = convert_u16(
    buffer[FILE_HEADER_OFFSETS.MINOR .. FILE_HEADER_OFFSETS.MINOR + BYTE_OFFSET / 2], e);
  file_header.snapLen = convert_u32(
    buffer[FILE_HEADER_OFFSETS.SNAP_LEN .. FILE_HEADER_OFFSETS.SNAP_LEN + BYTE_OFFSET], e);
  file_header.linkType = convert_u16(
    buffer[FILE_HEADER_OFFSETS.LINK_TYPE .. FILE_HEADER_OFFSETS.LINK_TYPE + BYTE_OFFSET / 2], e);
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

PACKET_HEADER* get_packet_header(FILE* f, ENDIAN e) @nogc
{
  ubyte[PACKET_HEADER_LENGTH] buffer;
  fread(buffer.ptr, 1, PACKET_HEADER_LENGTH, f);
  PACKET_HEADER* ph = cast(PACKET_HEADER*) malloc(PACKET_HEADER.sizeof);
  ph.seconds = convert_u32(
    buffer[PACKET_HEADER_OFFSETS.SECONDS .. PACKET_HEADER_OFFSETS.SECONDS + BYTE_OFFSET], e);
  ph.micro_nano = convert_u32(
    buffer[PACKET_HEADER_OFFSETS.MICRO_NANO .. PACKET_HEADER_OFFSETS.MICRO_NANO + BYTE_OFFSET], e);
  ph.capturedLength = convert_u32(
    buffer[PACKET_HEADER_OFFSETS.CAP_LEN .. PACKET_HEADER_OFFSETS.CAP_LEN + BYTE_OFFSET], e);
  ph.originalLength = convert_u32(
    buffer[PACKET_HEADER_OFFSETS.OG_LEN .. PACKET_HEADER_OFFSETS.OG_LEN + BYTE_OFFSET], e);

  return ph;
}

struct PACKET_DATA
{
  int id;
  PACKET_HEADER* packet_header;
  ubyte* data;
  PACKET_DATA* next;
  PACKET_DATA* prev;
}

static int PACKET_COUNT = 0;
static PACKET_DATA* head;

PACKET_DATA* get_packet_data(FILE* f, PACKET_HEADER* packet_header) @nogc
{
  PACKET_DATA* packet_data = cast(PACKET_DATA*) malloc(PACKET_DATA.sizeof);
  if (packet_data is null)
  {
    free(packet_data);
    return null;
  }
  ubyte* data = cast(ubyte*) malloc(ubyte.sizeof * packet_header.capturedLength);
  if (data is null)
  {
    free(data);
    return null;
  }
  size_t bytes_read = fread(data, 1, packet_header.capturedLength, f);
  if (bytes_read != packet_header.capturedLength)
  {
    free(data);
    free(packet_data);
    return null;
  }
  packet_data.data = data;
  packet_data.packet_header = packet_header;
  return packet_data;
}

int add_packet_data(PACKET_DATA* packet_data) @nogc
{
  if (packet_data is null)
  {
    return -1;
  }
  packet_data.id = PACKET_COUNT++;
  if (head is null)
  {
    head = packet_data;
    head.next = packet_data;
    head.prev = packet_data;
    return 1;
  }
  else
  {
    packet_data.next = head;
    packet_data.prev = head.prev;
    head.prev.next = packet_data;
    head.prev = packet_data;
    return 1;
  }

  return -1;
}

void read_file(FILE* fp, ENDIAN e) @nogc
{
  while (!(feof(fp)))
  {
    PACKET_HEADER* packet_header = get_packet_header(fp, e);
    if (packet_header is null)
    {
      free(packet_header);
      break;
    }

    PACKET_DATA* packet_data = get_packet_data(fp, packet_header);
    if (packet_data is null)
    {
      free(packet_data);
      break;
    }

    if (add_packet_data(packet_data) < 0)
    {
      break;
    }

  }

  return;
}

void traverse_packet_data()
{
   if (head is null)
    return;

  PACKET_DATA* current = head;

  printf("%-10s | %-16s | %-15s\n", 
    cast(const char*)"Packet ID",
    cast(const char*)"Bytes Captured",
    cast(const char*)"Arrival Time");

  printf("-----------+------------------+-------------------\n");

  do
  {
    printf("%-10d | %-16d | %u.%06u\n",
      current.id,
      current.packet_header.capturedLength,
      current.packet_header.seconds,
      current.packet_header.micro_nano);

    current = current.next;
  }
  while (current != head);
}


void free_packet_data(PACKET_DATA *packet_data)
{
  if (packet_data is null )
  {
    return;
  }
  free(packet_data.packet_header);
  free(packet_data.data);
  free(packet_data);
}

void free_packets()
{
  if (head is null)
    return;

  PACKET_DATA* curr = head;
  PACKET_DATA* next;

  do
  {
    next = curr.next;
    free_packet_data(curr);
    curr = next;
  }
  while (curr != head);

  head = null;
}
