# input=$1

# ldc2 -w  --vgc  ./source/*.d -of=bin/pcap

# ./bin/pcap $input


#!/bin/bash

input="$1"

# Compile with debug symbols and no optimization
ldc2 -g ./source/*.d -of=bin/pcap

# Run with Valgrind
valgrind --leak-check=full --track-origins=yes ./bin/pcap "$input"
