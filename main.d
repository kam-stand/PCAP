import std.stdio;
import std.file;
import pcap;
import system;
import std.range;
import std.algorithm;

import std.stdint;

import core.stdc.stdio;

enum int EXIT_SUCCESS = 0;

enum int EXIT_FAILURE = -1;

int main(string[] args)
{
    if (args.length < 2)
    {
        return EXIT_FAILURE;
    }
    if (!system.verifyFile(args[1]))
    {
        writeln("Please provde a file with a pcap extension");
        return EXIT_FAILURE;
    }

    ubyte[] content = read_content(args[1]);
    ENDIAN e = determineEndian(content);
    writeln(getHeader(content, e));
    // writeln(content[0 .. MAGIC_HEADER]);
    // each!(a => writef("%02x ", a))(content[0 .. MAGIC_HEADER]);
    // writeln();
    switch (e)
    {
    case ENDIAN.Little:
        auto c = chunks(content, 4);
        //writeln(c[0]);
        //each!(a => writef("%02x ", a))(c[0]);
        writeln();
        writefln("MAGIC NUMBER: %02x", system.read_u32(content, e));
        break;
    case ENDIAN.Big:
        writefln("MAGIC NUMBER: %02x", system.read_u32(content, e));
        break;
    default:
        break;
    }

    return EXIT_SUCCESS;
}
