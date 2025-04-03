input=$1

ldc2 -wi ./*.d

./main $input

rm ./*.o ./main