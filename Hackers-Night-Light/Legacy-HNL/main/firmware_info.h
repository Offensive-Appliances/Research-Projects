#ifndef LEGACY_HNL_FIRMWARE_INFO_H
#define LEGACY_HNL_FIRMWARE_INFO_H

#include <stddef.h>

#define FW_NAME        "Legacy-HNL"
#define FW_VERSION     "1.0"

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

#endif // LEGACY_HNL_FIRMWARE_INFO_H
