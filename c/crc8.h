#ifndef IK_CRC8_H
#define IK_CRC8_H

#include <stdint.h>
#include <stddef.h>

uint8_t ik_crc8(uint8_t crc, uint8_t const *data, size_t len);

#endif
