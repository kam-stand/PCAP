module system;
import std.stdio;

import std.stdint;

/*
* 1. determine endian
* 2. set the magic number
*
*/

enum MAGIC_NUMBER_BIG : uint32_t
{
    V1 = 0xA1B2C3D4,
    V2 = 0xA1B23C4D
}


enum MAGIC_NUMBER_LITTLE : uint32_t
{
    V1 = 0xD4C3B2A1,
    V2 = 0x4D3CB2A1
}


enum ENDIAN : int
{
    LITTLE,
    BIG,
    INVALID
}

enum MAGIC_HEADER_LENGTH = 4; // first 4 bytes are the magic numbers

ENDIAN determineEndian(File f)
{
    ubyte[MAGIC_HEADER_LENGTH] magic;
        // interpret as little endian
    uint32_t magicLittle = 
        (cast(uint32_t)magic[0]) |
        (cast(uint32_t)magic[1] << 8) |
        (cast(uint32_t)magic[2] << 16) |
        (cast(uint32_t)magic[3] << 24);

    // interpret as big endian
    uint32_t magicBig = 
        (cast(uint32_t)magic[3]) |
        (cast(uint32_t)magic[2] << 8) |
        (cast(uint32_t)magic[1] << 16) |
        (cast(uint32_t)magic[0] << 24);

    if (magicLittle == MAGIC_NUMBER_LITTLE.V1 || MAGIC_NUMBER_LITTLE.V2) return ENDIAN.LITTLE;
    if (magicBig == MAGIC_NUMBER_BIG.V1 || MAGIC_NUMBER_BIG.V2) return ENDIAN.BIG;

    return ENDIAN.INVALID;
}


uint32_t convert_u32(ubyte[] content, ENDIAN e)
{
    uint32_t value;
    switch(e)
    {
        case ENDIAN.LITTLE:
            value = 
            (cast(uint32_t)content[0]) |
            (cast(uint32_t)content[1] << 8) |
            (cast(uint32_t)content[2] << 16) |
            (cast(uint32_t)content[3] << 24);
            return value;
        case ENDIAN.BIG:
            value = 
            (cast(uint32_t)content[3]) |
            (cast(uint32_t)content[2] << 8) |
            (cast(uint32_t)content[1] << 16) |
            (cast(uint32_t)content[0] << 24);
            return value;
        default:
            break;
    }
    return value;
}


uint16_t convert_u16(ubyte[] content, ENDIAN e)
{
    uint16_t value;
    switch(e)
    {
        case ENDIAN.LITTLE:
            value = 
            (cast(uint16_t)content[0]) |
            (cast(uint16_t)content[1] << 8);
            return value;
        case ENDIAN.BIG:
            value = 
            (cast(uint16_t)content[1]) |
            (cast(uint16_t)content[0] << 8);
            return value;
        default:
            break;
    }
    return value;
}