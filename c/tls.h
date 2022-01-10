#ifndef IK_TLS_H
#define IK_TLS_H

#include "identity.h"
#include <stdio.h>

/// create an x509 PEM encoded certificate self signed by the secret
int ik_tls_make_cert(FILE *fp, ik_secret secret);

#endif
