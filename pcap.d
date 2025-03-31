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

uint32_t decode_32(ref ubyte[4] content)
{
    uint32_t value = (content[3] << 24) |
                     (content[2] << 16) |
                     (content[1] << 8) |
                     (content[0]);
    return value;
                    
}

uint16_t decode_16(ref ubyte[2] content)
{
    uint16_t value = (content[1] << 8) |
                     (content[0]);
    return value;
                    
}
bool validMagic(uint32_t magic)
{
    return (magic == MAGIC1) || (magic == MAGIC2);
}



uint32_t readMagic(ref ubyte[4] content)
{
    uint32_t magic = decode_32(content);
    writeln(validMagic(magic));
    return magic;

}



