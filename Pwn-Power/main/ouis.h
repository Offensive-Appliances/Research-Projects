#ifndef OUIS_H
#define OUIS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool ouis_lookup_vendor(const uint8_t *mac, char *out_vendor, size_t out_sz);

#endif
