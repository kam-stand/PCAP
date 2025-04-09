input=$1

ldc2 -w  --vgc ./source/*.d -of=bin/pcap

./bin/pcap $input