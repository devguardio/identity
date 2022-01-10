#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>

#include "identity.h"
#include "error.h"

static int add_ext (X509 *cert, int nid, char *value )
{
    X509_EXTENSION *ex = NULL;
    X509V3_CTX ctx;
    // Setting context of Extension
    X509V3_set_ctx_nodb ( &ctx );
    // Issuer and subject certs: both the target since it is self signed, no
    // request and no CRL
    X509V3_set_ctx( &ctx, cert, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid (NULL, &ctx, nid, value );
    if(!ex) {
        return IK_ERR_OPENSSL_FAILED;
    }
    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);

    return 0;
}

int ik_tls_make_cert(FILE *out, ik_secret secret) {

    EVP_PKEY_CTX *ctx   = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *pkey      = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, secret, sizeof(ik_secret));

#ifdef INTERMEDIATE_DEBUG
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);

    EVP_PKEY_print_private(bp, pkey, 5, NULL);
    BIO_free(bp);
#endif

    // starting generation of x509 based on this pkey
    X509 *x509 = X509_new();
    X509_set_version(x509, 2); // for X509v3 should be value 2

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_NAME * x509_name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(x509_name, "OU", MBSTRING_ASC,
            (unsigned char*)"identitykit", -1, -1, 0);
    X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
            (unsigned char*)"COMMON NAME",   -1, -1, 0);
    X509_set_issuer_name(x509, x509_name);

    time_t before = 0;
    time(&before);
    before -= 3600; // one hour before now
    X509_time_adj_ex(X509_getm_notBefore(x509), 0, 0, &before);

    time_t after = 0;
    time(&after);
    after += 3600 * 1000000L;
    X509_time_adj_ex(X509_getm_notAfter(x509), 0, 0, &after);

    // IsCA:                   true,
    add_ext(x509, NID_basic_constraints,  "critical, CA:TRUE" );

    // BasicConstraintsValid:  true,
    // KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
    add_ext ( x509, NID_key_usage, "digitalSignature, keyCertSign" );

    // ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
    add_ext(x509, NID_ext_key_usage, "serverAuth, clientAuth");

    if (X509_set_pubkey(x509, pkey) == 0) {
        return IK_ERR_OPENSSL_FAILED;
    }
    if (X509_sign(x509, pkey, NULL) == 0) {
        return IK_ERR_OPENSSL_FAILED;
    }

//  c.DNSNames = append(c.DNSNames, opt.DNSNames...);

    PEM_write_X509(out, x509);

    X509_free(x509);
    EVP_PKEY_CTX_free(ctx);
    return 0;
}

