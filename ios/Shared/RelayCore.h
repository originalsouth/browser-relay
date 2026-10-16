#ifndef RELAY_CORE_H
#define RELAY_CORE_H
#include <stdint.h>
#include <stddef.h>
// The result is owned UTF-8 JSON; release it exactly once with relay_core_free.
char *relay_core_request(const uint8_t *bytes, size_t length);
void relay_core_free(char *value);
#endif
