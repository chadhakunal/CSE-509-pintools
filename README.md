# CSE-509-pintools

PIN_ROOT=/home/sekar/Desktop/pin-kit make <br>
~/Desktop/pin-kit/pin -t obj-intel64/InstructionCount.so -- /bin/ls


g++ -fno-stack-protector -z execstack -o overflow_example overflow_example.cpp