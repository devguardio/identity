#ifndef IK_ERROR_H
#define IK_ERROR_H

#define IK_ERR_BUFFER_TOO_SMALL (-1)
#define IK_ERR_INVALID_BASE32   (-2)
#define IK_ERR_NOT_IMPL         (-3)
#define IK_ERR_URANDOM          (-4)
#define IK_ERR_INSTR_TOO_SMALL  (-5)
#define IK_ERR_INSTR_INVALID    (-6)
#define IK_ERR_CHECKSUM         (-7)
#define IK_ERR_UNEXPECTED_TYPE  (-8)
#define IK_ERR_OPENSSL_FAILED   (-9)

static inline const char * ik_strerr(int e) {
    switch (e) {
        case IK_ERR_BUFFER_TOO_SMALL:   return "buffer too small";
        case IK_ERR_INVALID_BASE32:     return "invalid base32";
        case IK_ERR_NOT_IMPL:           return "not implemented";
        case IK_ERR_URANDOM:            return "cannot read from /dev/urandom";
        case IK_ERR_INSTR_TOO_SMALL:    return "input string too small";
        case IK_ERR_INSTR_INVALID:      return "input string invalid";
        case IK_ERR_CHECKSUM:           return "invalid checksum";
        case IK_ERR_UNEXPECTED_TYPE:    return "expected a different type";
        case IK_ERR_OPENSSL_FAILED:     return "unhandled failure  in openssl library";
    }
    return "unknown error";
}

#endif
