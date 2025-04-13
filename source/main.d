import std.stdio;
import system;
import headers;
import ethernet;


void main(string[] args) 
{
    File f = File(args[1], "rb");
    ENDIAN e = determineEndian(f);
    writeln(e);
    FILE_HEADER fh = getFileHeader(f, e);
    writefln("Size of file header: %d", FILE_HEADER_LENGTH);
    // PACKET_HEADER ph = getPacketHeader(f, e);
    // PACKET_DATA pd = getPacketData(f, e, ph);
    // ETHERNET_HEADER et = getEthernetHeader(pd, e);

    while (!(f.eof))
    {
        PACKET_HEADER ph = getPacketHeader(f, e);
        writefln("Size of packet header: %d", PACKET_HEADER_LENGTH);
        PACKET_DATA pd = getPacketData(f, e, ph);
        writefln("Size of packet data %d: ", pd.data.length);
    }

    f.close();
}
