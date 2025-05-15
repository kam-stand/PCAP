import core.stdc.stdio;
import core.stdc.stdlib;

import system;
import headers;
import ethernet;

extern(C) int main(int argc, char **argv)
{
    char *file_name = argv[1];

    
    ENDIAN e = determineEndian(file_name);
    printf("The endian is %d\n", e);
    FILE *f = fopen(file_name, "rb");
    FILE_HEADER file_header = get_file_header(f, e);

    read_file(f, e);
    traverse_packet_data();
    free_packets();

    return 0;
}
