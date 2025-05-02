import std.stdio;
import system;
import headers;
import ethernet;

void main(string[] args)
{
    File f = File(args[1], "rb");
    ENDIAN e = determineEndian(f);
    writefln("File is %s endian", e);
    FILE_HEADER fh = getFileHeader(f, e);


    while (!(f.eof()))
    {
        PACKET_HEADER ph = getPacketHeader(f, e);
        PACKET_DATA pd = getPacketData(f, e, ph);
        pd.index = PACKET_COUNT++;
        PCAP_PACKETS ~= pd;
    }

    foreach (PACKET_DATA key; PCAP_PACKETS)
    {
     writefln("Data size is %d", key.data.length);   
    }

    f.close();
}
