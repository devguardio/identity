#include "ik/identity.h"
#include "ik/error.h"
#include "ik/rand.h"
#include "ik/crc8.h"
#include "ik/base32.h"
#include <string.h>
#include <alloca.h>
#include "crypto/ed25519/ed25519.h"

int ik_secret_create(ik_secret * out) {
    return ik_rand((uint8_t*)out, 32);
}

int ik_secret_to_string(const ik_secret *in, char *out, size_t outlen) {
    return ik_to_string((const uint8_t*)in, 32, out, outlen, IK_TYPE_SECRET);
}

int ik_secret_from_string (ik_secret *out, const char *in, size_t inlen) {
    uint8_t typ = 0;
    int r = ik_from_string  ((uint8_t*)out, 32, in, inlen, &typ);
    if (r < 0) {return r;}
    if (typ != IK_TYPE_SECRET) { return IK_ERR_UNEXPECTED_TYPE; }
    return r;
}

int ik_identity_to_string(const ik_identity *in, char *out, size_t outlen) {
    return ik_to_string((const uint8_t*)in, 32, out, outlen, IK_TYPE_IDENTITY);
}

int ik_identity_from_string (ik_secret *out, const char *in, size_t inlen) {
    uint8_t typ = 0;
    int r = ik_from_string  ((uint8_t*)out, 32, in, inlen, &typ);
    if (r < 0) {return r;}
    if (typ != IK_TYPE_IDENTITY) { return IK_ERR_UNEXPECTED_TYPE; }
    return r;
}

int ik_to_string    (const uint8_t *in, size_t inlen, char *out, size_t outlen, uint8_t typ) {

    if (outlen < 3 || inlen > 64) {
        return IK_ERR_BUFFER_TOO_SMALL;
    }

    uint8_t b[64 + 2] = {0};
    size_t bs = 0;

    if (typ == IK_TYPE_SEQUENCE ) {
        out[0] = '+';
    } else {
        out[0] = 'c';

        b[0] = IK_VERSION << 4 | typ;
        bs += 1;
    }

    size_t i = 0;
    for (; i < inlen; i++) {
        b[bs] = in[i];
        bs += 1;
    }

    if (typ != IK_TYPE_SEQUENCE) {

        uint8_t crc = ik_crc8(0, b, 1);
        crc = ik_crc8(crc, in, inlen);

        b[bs] = crc;
        bs += 1;
    }

    int r = ik_base32_encode(b, bs, out + 1 , outlen - 1);
    if (r < 0) { return r; }
    return 1 + r;
}

int ik_from_string  (uint8_t *out, size_t outlen, const char *in, size_t inlen, uint8_t *typ) {

    if (inlen < 3) {
        return IK_ERR_INSTR_TOO_SMALL;
    }

    if (in[0] != 'c' && in[0] != '+' && in[0] != '=') {
        return IK_ERR_INSTR_INVALID;
    }

    uint8_t * b = alloca(inlen);

    int r = ik_base32_decode(in + 1, inlen -1, b , inlen);
    if (r < 0) { return r;}

    if (in[0] == '+' || in[0] == '=') {
        *typ = IK_TYPE_SEQUENCE;
        memcpy(out, b , r);
        return r;
    }

    if (r < 3) {
        return IK_ERR_INSTR_TOO_SMALL;
    }

    if (b[0] >> 4 != 1) {
        return IK_ERR_INSTR_INVALID;
    }

    uint8_t crc = ik_crc8(0, b, r - 1);

    if (crc != b[r-1]) {
        return IK_ERR_CHECKSUM;
    }


    *typ = (b[0] & 0x0f);
    memcpy(out, b + 1 , r - 1);
    return r - 2;
}

int identity_from_secret (ik_identity *out, const ik_secret * in) {
    ed25519_publickey(*in, *out);
    return 0;
}


