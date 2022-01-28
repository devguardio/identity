package tls

import (
    "github.com/devguardio/identity/go"
    "crypto/ed25519"
    "crypto/x509"
    //"time"
    "errors"
    "crypto/tls"
)


func ClaimedPeerIdentity(c*tls.ConnectionState) identity.Identity {
    // the claimed id ca is the last certificate
    var idCert = c.PeerCertificates[len(c.PeerCertificates)-1];
    var id identity.Identity;

    pkey, ok := idCert.PublicKey.(ed25519.PublicKey);
    if !ok {
        panic(errors.New("tls: claimed identity not ed25519. this should have been cought by identity.VerifyPeerCertificate"));
    }

    copy(id[:], pkey[:]);
    return id;
}


func VerifyPeerIdentity(expected *identity.Identity) func (certificates [][]byte, verifiedChains [][]*x509.Certificate) error {
    return func (certificates [][]byte, verifiedChains [][]*x509.Certificate) error {
        return verifyPeerIdentity(certificates, verifiedChains, []*identity.Identity{expected})
    }
}

func VerifyPeerCertificate (certificates [][]byte, verifiedChains [][]*x509.Certificate) error {
    return verifyPeerIdentity(certificates, verifiedChains, nil)
}

func verifyPeerIdentity(certificates [][]byte, verifiedChains [][]*x509.Certificate, trusted []*identity.Identity) error {

    certs := make([]*x509.Certificate, len(certificates))
    var err error
    for i, asn1Data := range certificates {
        if certs[i], err = x509.ParseCertificate(asn1Data); err != nil {
            return errors.New("tls: failed to parse client certificate: " + err.Error())
        }
    }

    var idCert *x509.Certificate

    if len(certs) == 0 {
        return errors.New("tls: client didn't provide a certificate")
    } else if len(certs) == 1 {

        // self signed
        idCert = certs[0];

    } else if len(certs) == 2 {

        // the claimed id is the root cert, which is always last
        idCert = certs[1];

        // verify that the subcert is signed by the root
        subCert := certs[0];

        err = subCert.CheckSignatureFrom(idCert);
        if err != nil { return errors.New("subcert not signed by root: " + err.Error()) }

    } else {
        return errors.New("tls: cert chains longer than 2 are difficult to argue about, so we don't support it")
    }

    pkey, ok := idCert.PublicKey.(ed25519.PublicKey);
    if !ok { return errors.New("tls: claimed identity not ed25519"); }

    var id identity.Identity;
    copy(id[:], pkey[:]);

    cacert, err := id.ToCertificate();
    if err != nil { return err }

    err = idCert.CheckSignatureFrom(cacert);
    if err != nil { return errors.New("failed checking if client presented root is signed by the claimed identity: " + err.Error()) }


    if len(trusted) > 0 {
        for _, trust := range trusted {
            if trust.Equal(&id) {
                return nil
            }
        }
        return errors.New("unexpected remote identity " + id.String())
    }

    return nil
}


func NewTlsClient(vault identity.VaultI) (*tls.Config, error) {

    key, err := vault.ExportSecret()
    if err != nil { return nil, err }

    pub, err := vault.Identity();
    if err != nil { return nil, err }

    cert, err := pub.ToCertificate();
    if err != nil { return nil, err }

    der, err := vault.SignCertificate(cert, pub);
    if err != nil { return nil, err }

    tcert := tls.Certificate{
        Certificate: [][]byte{der},
        PrivateKey: key.ToGo(),
    }

    tlsconfig := &tls.Config{
        RootCAs:        x509.NewCertPool(),
        Certificates:   []tls.Certificate{tcert},
    }

    return tlsconfig, nil
}
