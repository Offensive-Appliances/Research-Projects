#include "firmware_info.h"

const char* firmware_get_version(void) {
    return FW_VERSION;
}

const char* firmware_get_name(void) {
    return FW_NAME;
}

const char* firmware_get_build_date(void) {
    return FW_BUILD_DATE;
}

const char* firmware_get_target(void) {
    return FW_TARGET;
}
