module system;
import std.stdio;

import core.stdc.stdio;
import core.stdc.stdint;

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

ENDIAN determineEndian(char* file_name)
{
    FILE* fp = fopen(file_name, "rb");
    ubyte[MAGIC_HEADER_LENGTH] buffer;
    size_t bytesRead = fread(buffer.ptr, 1, MAGIC_HEADER_LENGTH, fp);
    assert(bytesRead == MAGIC_HEADER_LENGTH);

    uint littleEndian =
        cast(uint) buffer[0] |
        (cast(uint) buffer[1] << 8) |
        (cast(uint) buffer[2] << 16) |
        (cast(uint) buffer[3] << 24);
    uint bigEndian =
        cast(uint) buffer[3] |
        (cast(uint) buffer[2] << 8) |
        (cast(uint) buffer[1] << 16) |
        (cast(uint) buffer[0] << 24);

    if (bigEndian == MAGIC_NUMBER_BIG.V1 || bigEndian == MAGIC_NUMBER_BIG.V2)
    {
        fclose(fp);
        return ENDIAN.BIG;
    }
    else if (littleEndian == MAGIC_NUMBER_BIG.V1 || littleEndian == MAGIC_NUMBER_BIG.V2)
    {
        fclose(fp);
        return ENDIAN.LITTLE;
    }
    else
    {
        fclose(fp);
        return ENDIAN.INVALID;
    }
    fclose(fp);
    return ENDIAN.INVALID;

}

uint32_t convert_u32(ubyte[4] content, ENDIAN e) @nogc
{
    uint32_t value;
    switch (e)
    {
    case ENDIAN.LITTLE:
        value =
            (cast(uint32_t) content[0]) |
            (cast(uint32_t) content[1] << 8) |
            (
                cast(uint32_t) content[2] << 16) |
            (cast(uint32_t) content[3] << 24);
        return value;
    case ENDIAN.BIG:
        value =
            (cast(uint32_t) content[3]) |
            (cast(uint32_t) content[2] << 8) |
            (
                cast(uint32_t) content[1] << 16) |
            (cast(uint32_t) content[0] << 24);
        return value;
    default:
        break;
    }
    return value;
}

uint16_t convert_u16(ubyte[2] content, ENDIAN e) @nogc
{

    uint16_t value;
    switch (e)
    {
    case ENDIAN.LITTLE:
        value =
            (cast(uint16_t) content[0]) |
            (cast(uint16_t) content[1] << 8);
        return value;
    case ENDIAN.BIG:
        value =
            (cast(uint16_t) content[1]) |
            (cast(uint16_t) content[0] << 8);
        return value;
    default:
        break;
    }
    return value;
}
