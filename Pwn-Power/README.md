# PwnPower

This firmware is a simple Scanner with Deauth and Handshake Capture built using ESP-IDF, made for the ESP32C3 chip.


## Requriments 
- ESP-IDF v5.5 or newer
- ESP32C3

## Build and Flash Instructions 
1. Create new esp-idf project 
2. Select esp32 c3 as target, requires preview verison `idf.py --preview set-target esp32c3`
3. Place firmware files in the `/main` directory of your project. (Replace the CMakeLists file that is auto generated with new one)
4. Build the firmware `idf.py build`
5. Flash Firmware to C3 `idf.py flash` 

if you experience issues during this process, try `idf.py fullclean` and restart. 


## Post flash instructions
Once your device is flashed and booted, it will host a wifi AP by the name of `PwnPower`.
By default, the password is `password` if you wish to change this, you can modify the AP name and AP password on lines `15` & `16`

once connected to the pwnpower ap, open a web browser and navigate to `192.168.4.1` and click/touch `wifi recon`. info updates every 8 seconds. 


## NOTICE 

This firmware was written purely as an example, use at your own risk and responsibility, there is no guarantee for support. 

