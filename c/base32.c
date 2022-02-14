#include <string.h>
#include <stdint.h>
#include "ik/base32.h"
#include "ik/error.h"

const char * ALPHABET   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

static void encode_base32_block(const uint8_t * from, char * to)
//    where len(from) >= 5
//    where len(to)   >= 8
{
    uint8_t c1 = ((  from[0] & 0xf8) >> 3);
    uint8_t c2 = ((( from[0] & 0x07) << 2) | ((  from[1] & 0xc0) >> 6));
    uint8_t c3 = ((  from[1] & 0x3e) >> 1);
    uint8_t c4 = ((( from[1] & 0x01) << 4) | ((  from[2] & 0xf0) >> 4));
    uint8_t c5 = ((( from[2] & 0x0f) << 1) | (   from[3] >> 7));
    uint8_t c6 = ((  from[3] & 0x7c) >> 2);
    uint8_t c7 = ((( from[3] & 0x03) << 3) | ((  from[4] & 0xe0) >> 5));
    uint8_t c8 = (   from[4] & 0x1f);

    to[0] = ALPHABET[c1];
    to[1] = ALPHABET[c2];
    to[2] = ALPHABET[c3];
    to[3] = ALPHABET[c4];
    to[4] = ALPHABET[c5];
    to[5] = ALPHABET[c6];
    to[6] = ALPHABET[c7];
    to[7] = ALPHABET[c8];
}

int ik_base32_encode(const uint8_t *src, size_t inlen, char * out, size_t outlen)
//    where err::checked(*e)
//    where inlen   <= len(src)
//    where outlen <= len(out)
{
    size_t at_in  = 0;
    size_t at_out = 0;

    for (;;) {
        size_t size_left = inlen - at_in;
        if (size_left  >= 5) {
            if (at_out + 8 >= outlen)  {
                return -1;
            }
            encode_base32_block(src + at_in, out + at_out);
            at_in  += 5;
            at_out += 8;
        } else if (size_left == 0) {
            break;
        } else {
            uint8_t mi[5] = {0};
            memcpy(mi, (uint8_t*)(src + at_in), size_left);
            if (at_out + 8 >= outlen)  {
                return IK_ERR_BUFFER_TOO_SMALL;
            }
            encode_base32_block(mi, out + at_out);

            switch (size_left) {
                case 1: {
                    out[at_out + 2] = 0;
                    at_out += 2;
                    break;
                }
                case 2: {
                    out[at_out + 4] = 0;
                    at_out += 4;
                    break;
                }
                case 3: {
                    out[at_out + 5] = 0;
                    at_out += 5;;
                    break;
                }
                case 4: {
                    out[at_out + 7] = 0;
                    at_out += 7;
                    break;
                }
            }
            break;
        }
    }

    return at_out;
}


int ik_base32_decode(const char *src, size_t inlen, uint8_t * out, size_t outlen)
//    where err::checked(*e)
//    where inlen   <= len(src)
//    where outlen <= len(out)
{
    uint8_t LOOKUP[] = {-1, -1, 26, 27, 28, 29, 30, 31, -1, -1, -1, -1, -1, 0, -1, -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25};

    size_t at_in  = 0;
    size_t at_out = 0;

    for (;;) {
        size_t size_left = inlen - at_in;
        if (size_left == 0) {
            break;
        }
        uint8_t block[8] = {0};
        for (size_t i = 0; i < 8 && i < size_left; i++) {
            size_t lo = (size_t)(src[at_in + i]) - (size_t)('0');
            if (lo >= sizeof(LOOKUP)) {
                return IK_ERR_INVALID_BASE32;
            }
            block[i] = LOOKUP[lo];
        }

        if (at_out + 4 >= outlen)  {
            return IK_ERR_BUFFER_TOO_SMALL;
        }

        out[at_out + 0] = (block[0] << 3) | (block[1] >> 2);
        out[at_out + 1] = (block[1] << 6) | (block[2] << 1) | (block[3] >> 4);
        out[at_out + 2] = (block[3] << 4) | (block[4] >> 1);
        out[at_out + 3] = (block[4] << 7) | (block[5] << 2) | (block[6] >> 3);
        out[at_out + 4] = (block[6] << 5) | block[7];

        at_in  += 8;
        at_out += 5;

        if (size_left  <  8) {
            break;
        }
    }

    return inlen * 5 / 8;
}

