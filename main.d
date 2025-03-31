import std.stdio;
import std.file;
import pcap;

enum int EXIT_SUCCESS = 0;

enum int EXIT_FAILURE = -1;

int main(string[] args)
{
    if (args.length < 2)
    {
        return EXIT_FAILURE;
    }

    string file_path = args[1];
    ubyte[] content = cast(ubyte [])read(file_path);
    //writeln(readMagic(content[0..4]));
    writeln(content[0..4]);
    return EXIT_SUCCESS;

}

