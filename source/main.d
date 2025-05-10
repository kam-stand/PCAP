import core.stdc.stdio;
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

    printf("The link type is %02x\n", file_header.linkType);
    printf("The major is %02x\n", file_header.major);
    printf("The minor is %02x\n", file_header.minor);
    printf("The spanLen is %ld\n", file_header.snapLen);

    PACKET_HEADER ph = get_packet_header(f, e);

    printf("The micro_nano is %ld\n", ph.micro_nano);
    printf("The capturedLength is %ld\n", ph.capturedLength);
    printf("The originalLength is %ld\n", ph.originalLength);
    printf("The seconds is %ld\n",ph.seconds);


    return 0;
}
