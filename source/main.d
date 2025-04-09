import std.stdio;
import system;
import headers;


void main(string[] args) 
{
    File f = File(args[1], "rb");
    ENDIAN e = determineEndian(f);
    FILE_HEADER fh = getFileHeader(f, e);
    PACKET_HEADER ph = getPacketHeader(f, e);
    PACKET_DATA pd = getPacketData(f, e, ph);
    decodePacketData(pd, cast(LINK_TYPE)fh.linkType);
    f.close();
}
