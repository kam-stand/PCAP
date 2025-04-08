input=$1

ldc2 -w ./source/*.d -of=bin/pcap

./bin/pcap $input