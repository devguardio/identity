#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "ik/identity.h"
#include "ik/error.h"
#include "ik/tls.h"

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/err.h>

int load_ca(SSL_CTX *ctx , const ik_secret * secret, const ik_identity *public) {

    X509 *x509 = X509_new();
    int err = ik_tls_make_cert(x509, secret, public);

    if (err < 0) {
        X509_free(x509);
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        return 1;
    }

    X509_STORE_add_cert(SSL_CTX_get_cert_store(ctx), x509);
    X509_free(x509);

    return 0;
}

int load_key(SSL_CTX *ctx , const ik_secret * secret) {

    ik_identity pubkey;
    identity_from_secret (&pubkey, secret);

    X509 *x509 = X509_new();
    int err = ik_tls_make_cert(x509, secret, &pubkey);

    if (err < 0) {
        X509_free(x509);
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        return 1;
    }

    SSL_CTX_use_certificate(ctx, x509);
    X509_free(x509);

    EVP_PKEY *ssl_priv  = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, *secret, sizeof(ik_secret));
    SSL_CTX_use_PrivateKey(ctx, ssl_priv);
    EVP_PKEY_free(ssl_priv);

    return 0;
}

int main(int argc, char **argv) {

    if (argc < 3) {
        fprintf(stderr, "usage: ikc <secret> <remote-public>\n");
        return 1;
    }

    ik_secret secret;
    int err = ik_secret_from_string (&secret, argv[1], strlen(argv[1]));
    if (err < 0) {
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        return 1;
    }

    ik_identity public;
    err = ik_identity_from_string (&public, argv[2], strlen(argv[2]));
    if (err < 0) {
        fprintf(stderr, "cannot parse secret: %s\n", ik_strerr(err));
        return 1;
    }


    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) {
        printf("errored; unable to load context.\n");
        ERR_print_errors_fp(stderr);
        return -3;
    }

    load_ca(ctx, &secret, &public);
    load_key(ctx, &secret);

    BIO *bio = BIO_new_ssl_connect(ctx);

    SSL *ssl = 0;
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    BIO_set_conn_hostname(bio, "google.com:8443");

    SSL_set_tlsext_host_name(ssl, "duckduckgo.com");

    SSL_set_verify(ssl, SSL_VERIFY_PEER, NULL);

    if (BIO_do_connect(bio) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to connect.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    const char *request = "GET / HTTP/1.1\r\nHost: google.com\r\nConnection: Close\r\n\r\n";

    if (BIO_puts(bio, request) <= 0) {
        BIO_free_all(bio);
        printf("errored; unable to write.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }

    char tmpbuf[1024+1];

    for (;;) {
        int len = BIO_read(bio, tmpbuf, 1024);
        if (len == 0) {
            break;
        }
        else if (len < 0) {
            if (!BIO_should_retry(bio)) {
                printf("errored; read failed.\n");
                ERR_print_errors_fp(stderr);
                break;
            }
        }
        else {
            tmpbuf[len] = 0;
            printf("%s", tmpbuf);
        }
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);

    return 0;
}



