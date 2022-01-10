#ifndef BASE32_H
#define BASE32_H

#include <stddef.h>
#include <stdint.h>

int ik_base32_encode(const uint8_t *src, size_t inlen, char * out, size_t outlen);
int ik_base32_decode(const char *src, size_t inlen, uint8_t * out, size_t outlen);

#endif
