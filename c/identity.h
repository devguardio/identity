#ifndef IK_IDENTITY_H
#define IK_IDENTITY_H

#include <stdint.h>
#include <stddef.h>

#define PACKED __attribute__((__packed__))

#define IK_TYPE_SECRETKIT   1
#define IK_TYPE_SECRET      3
#define IK_TYPE_XSECRET     3
#define IK_TYPE_XPUBLIC     6
#define IK_TYPE_IDENTITY    9
#define IK_TYPE_PUBLIC      9
#define IK_TYPE_SIGNATURE   10
#define IK_TYPE_SEQUENCE    11

#define IK_VERSION          1

typedef uint8_t  ik_secret    [32];     // type 3
typedef uint8_t  ik_xsecret   [32];     // type 4
typedef uint8_t  ik_xpublic   [32];     // type 6
typedef uint8_t  ik_identity  [32];     // type 9
typedef uint8_t  ik_signature [64];     // type 10
typedef uint64_t ik_sequence;           // type 11
typedef struct PACKED { ik_secret identity; ik_secret network; }    ik_secretKit;   // type 1

int ik_to_string    (const uint8_t *in, size_t inlen, char *out, size_t outlen, uint8_t typ);
int ik_from_string  (uint8_t *out, size_t outlen, const char *in, size_t inlen, uint8_t *typ);

int ik_secret_create(ik_secret * out);
int ik_secret_to_string   (const ik_secret *in, char *out, size_t outlen);
int ik_secret_from_string (ik_secret *out, const char *in, size_t inlen);

int ik_identity_to_string   (const ik_identity *in, char *out, size_t outlen);
int ik_identity_from_string (ik_identity *out, const char *in, size_t inlen);

#endif
