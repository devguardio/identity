#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "identity.h"
#include "error.h"
#include "tls.h"


int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "secret key required\n");
        _exit(EXIT_FAILURE);
    }

    ik_secret secret;
    int err = ik_secret_from_string (&secret, argv[1], strlen(argv[1]));
    if (err < 0) {
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        _exit(EXIT_FAILURE);
    }


    FILE *f = fopen("cert.pem", "wb");
    err = ik_tls_make_cert(f, secret);
    fclose(f);
    if (err < 0) {
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        _exit(EXIT_FAILURE);
    }

    return 0;
}

