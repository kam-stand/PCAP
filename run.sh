pcap_file=$1
ldc2 -w ./src/*.d -of=bin/pcap
./bin/pcap $pcap_file


rm ./bin/pcap ./bin/*.o
