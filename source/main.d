import std.stdio;
import system;
import headers;


void main(string[] args) 
{
    File f = File(args[1], "rb");
    ENDIAN e = determineEndian(f);
    writeln(getFileHeader(f, e));
    writeln(getPacketHeader(f, e));
    f.close();
}
