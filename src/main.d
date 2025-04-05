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
    writeln(getPackets(content, e));
    

    return EXIT_SUCCESS;
}
