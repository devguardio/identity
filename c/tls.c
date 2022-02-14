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
#include <openssl/evp.h>

#include "ik/identity.h"
#include "ik/error.h"

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


// make an openssl cert
//
// first arg (x509) must be pre-allocated with X509_new()
// and freed with X509_free()
// to write to a FILE, use  PEM_write_X509(f, x509);
// 
int ik_tls_make_cert(X509 *x509, const ik_secret *secret, const ik_identity *pub) {

    EVP_PKEY_CTX *ctx   = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY *ssl_pub   = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, *pub, sizeof(ik_identity));
    EVP_PKEY *ssl_priv  = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, *secret, sizeof(ik_secret));


#ifdef INTERMEDIATE_DEBUG
    BIO *bp = BIO_new_fp(stdout, BIO_NOCLOSE);

    EVP_PKEY_print_private(bp, ssl_pub, 5, NULL);
    BIO_free(bp);
#endif

    X509_set_version(x509, 2); // for X509v3 should be value 2


    time_t before = 0;
    time(&before);
    before -= 3600; // one hour before now
    X509_time_adj_ex(X509_getm_notBefore(x509), 0, 0, &before);

    time_t after = 0;
    time(&after);
    after += 3600 * 1000000L;
    X509_time_adj_ex(X509_getm_notAfter(x509), 0, 0, &after);

    // BasicConstraintsValid:  true,
    // KeyUsage:               x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
    add_ext ( x509, NID_key_usage, "digitalSignature, keyCertSign" );

    // ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
    add_ext(x509, NID_ext_key_usage, "serverAuth, clientAuth");

    // IsCA:  true,
    add_ext(x509, NID_basic_constraints,  "critical, CA:TRUE" );


    // subject

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_NAME * x509_name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(x509_name, "O", MBSTRING_ASC,
            (unsigned char*)"identitykit", -1, -1, 0);

    char common_name[200];
    int common_name_len = ik_identity_to_string (pub, common_name, sizeof(common_name));

    X509_NAME_add_entry_by_txt(x509_name, "CN", MBSTRING_ASC,
            (unsigned char*)common_name,   common_name_len, -1, 0);
    X509_set_issuer_name(x509, x509_name);


    // subject key identifier

    char hexid[65] = {0};
    for (int i=0; i<32; i++) {
        hexid[i*2]   = "0123456789ABCDEF"[(*pub)[i] >> 4];
        hexid[i*2+1] = "0123456789ABCDEF"[(*pub)[i] & 0x0F];
    }

    add_ext(x509, NID_subject_key_identifier, hexid);


    if (X509_set_pubkey(x509, ssl_pub) == 0) {
        return IK_ERR_OPENSSL_FAILED;
    }
    if (X509_sign(x509, ssl_priv, NULL) == 0) {
        return IK_ERR_OPENSSL_FAILED;
    }

//  c.DNSNames = append(c.DNSNames, opt.DNSNames...);


    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(ssl_pub);
    EVP_PKEY_free(ssl_priv);
    return 0;
}

