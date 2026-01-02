sudo apt install -y libssl-dev

gcc -O2 -o ecu_can_ota ecu_can_ota_kdf.c -lcrypto

./ecu_can_ota can0 A12 0x12 ./secure_boot_serial/secure_boot_serial.txt ./update_files/receive.bin ./master_key.bin
