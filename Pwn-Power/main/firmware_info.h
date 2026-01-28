#ifndef PWNPOWER_FIRMWARE_INFO_H
#define PWNPOWER_FIRMWARE_INFO_H

#include <stddef.h>

#define FW_NAME        "PwnPower"
#define FW_VERSION     "2.0-BETA"

#ifdef CONFIG_IDF_TARGET
#define FW_TARGET      CONFIG_IDF_TARGET
#else
#define FW_TARGET      "ESP32"
#endif

#define FW_BUILD_DATE  __DATE__ " " __TIME__
#define FW_AUTHOR      "Offensive Appliances LLC"

#ifdef __cplusplus
extern "C" {
#endif

const char* firmware_get_version(void);
const char* firmware_get_name(void);
const char* firmware_get_build_date(void);
const char* firmware_get_target(void);

#ifdef __cplusplus
}
#endif

#endif // PWNPOWER_FIRMWARE_INFO_H
