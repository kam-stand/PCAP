module packet_data;
import std.stdio;
import std.stdint;


enum LINK_TYPE : uint16_t
{
  ETHERNET = 1,
  RAW_IP = 101,
  WIRELESS = 105,
  RAW_IPV4 = 228
}


struct ETHERNET
{
   
}