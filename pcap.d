module pcap;
import std.stdio;
import std.stdint;
import std.conv;
import std.bitmanip;


enum uint32_t MAGIC1 = 0xA1B2C3D4;
enum uint32_t MAGIC2 = 0xA1B23C4D;

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



