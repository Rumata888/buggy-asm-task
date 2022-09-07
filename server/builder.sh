git apply task.patch
g++ -D__BMI2__ -std=c++2a -I src/aztec task_lib.cpp src/aztec/crypto/sha256/sha256.cpp src/aztec/crypto/aes128/aes128.cpp -shared -fpic -o libdh.so
