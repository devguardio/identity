#include "base32.h"
#include "identity.h"
#include "error.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ASSERT(e)  { \
    if ((e) < 0) { \
        printf("test failure at %s:%d: %d %s\n", __FILE__, __LINE__, e, ik_strerr(e)); \
        abort(); \
    } \
} \

#define NASSERT(e)  { \
    if ((e) == 0) { \
        printf("test failure at %s:%d: %d %s\n", __FILE__, __LINE__, e, ik_strerr(e)); \
        abort(); \
    } \
} \

void test_secret() {
    ik_secret sk;
    int r = ik_secret_create(&sk);
    ASSERT(r);

    char buf[1000];
    r = ik_secret_to_string(&sk, buf, sizeof(buf));
    ASSERT(r);

    printf("%.*s\n", r, buf);

    ik_secret sk2;
    r = ik_secret_from_string(&sk2, buf, r);
    ASSERT(r);

    if (memcmp(&sk, &sk2, 32) != 0) {
        printf("not equal\n");
        abort();
    }
}

void test_identity() {

    const char *i1 = "cDE4VMOBKDTYU2NE3AOQBFJ4PO4YRE3RUTTCLLT5YDMICQSXPZYHQJKQ";
    ik_identity id;
    int r = ik_identity_from_string(&id, i1, strlen(i1));
    ASSERT(r);


    const char *i2 = "blurpington";
    r = ik_identity_from_string(&id, i2, strlen(i2));
    NASSERT(r)
}

int main() {

    test_secret();
    test_identity();

    printf("OK\n");
    return 0;
}
