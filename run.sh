input=$1

ldc2 -w -vgc ./*.d

./main $input

rm ./*.o ./main