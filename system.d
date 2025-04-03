module system;

import std.stdio;
import std.file;
import std.stdint;
import std.algorithm;
import std.conv;
import std.string;

import pcap;

enum FILE_EXTENSION : string 
{
    FILE1 = ".PCAP"
}

enum ENDIAN : int
{
    Little,
    Big,
    Invalid
}



enum MAGIC_NUMBERS : string
{
    MAGIC1 = "D4C3B2A1",
    MAGIC2 = "A1B2C3D4"
}

enum MAGIC_HEADER = 4;

bool verifyFile(in string file_path)
{
    return file_path[lastIndexOf(file_path, ".") .. $].toUpper() == FILE_EXTENSION.FILE1;
}

ubyte[] read_content(in string file_path)
{
    ubyte[] content = cast(ubyte[])read(file_path);
    return content; 
}


ENDIAN determineEndian(ref ubyte[] content)
{
    import std.digest;
    
    ubyte [] header = content[0..MAGIC_HEADER];
    string hex = toHexString(header);
    switch (hex)
    {
        case MAGIC_NUMBERS.MAGIC1:
            return ENDIAN.Little;
        case MAGIC_NUMBERS.MAGIC2:
            return ENDIAN.Big;
        default:
            break;
    }
    return ENDIAN.Invalid;
}

uint16_t read_u16(ref ubyte[] content, in ENDIAN endian)
{

    uint16_t value;
    switch (endian)
    {
        case ENDIAN.Little:
            value = (cast(uint16_t)(content[1]) << 8) |
                    cast(uint16_t)(content[0]);
            return value;
        case ENDIAN.Big:
            value = (cast(uint16_t)(content[0]) << 8) |
                    cast(uint16_t)(content[1]);
            return value;
        default:
            break;
    }

    return 0;
}



uint32_t read_u32(ref ubyte[] content, in ENDIAN endian)
{

    uint32_t value;
    switch (endian)
    {
        case ENDIAN.Little:
            value = (cast(uint32_t)(content[3]) << 24) |
                    (cast(uint32_t)(content[2]) << 16) |
                    (cast(uint32_t)(content[1]) << 8)  |
                    (cast(uint32_t)(content[0]));
            return value;

        case ENDIAN.Big:
            value = (cast(uint32_t)(content[0]) << 24) |
                    (cast(uint32_t)(content[1]) << 16) |
                    (cast(uint32_t)(content[2]) << 8)  |
                    (cast(uint32_t)(content[3]));
            return value;
        default:
            break;
    }

    return 0;

}

