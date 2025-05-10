import core.stdc.stdio;
import system;
import headers;
import ethernet;

extern(C) int main(int argc, char **argv)
{
    char *file_name = argv[1];
    FILE *f = fopen(file_name, "rb");
    ENDIAN e = determineEndian(f);


    return 0;
}
