package identity

import (
    "os"
    "log"
    "crypto/x509"
)

type VaultI interface {
    Init(interactive bool) error

    Domain(string) VaultI

    Identity()  (*Identity,     error)
    XPublic()   (*XPublic,      error)
    RSAPublic() (*RSAPublic,    error)

    Sign                (subject string, message []byte) (*Signature, error)
    SignCertificate     (template * x509.Certificate, pub *Identity)    ([]byte, error)
    SignRSACertificate  (template * x509.Certificate, pub *RSAPublic)   ([]byte, error)

    // will error for HSM, so use the other methods
    ExportSecret()    (*Secret,     error)
    ExportRSASecret() (*RSASecret,  error)
}

func Vault() VaultI {

    sks := os.Getenv("IDENTITYKIT_SECRET")
    if sks != "" {
        sk, err := SecretFromString(sks)
        if err == nil {
            return &StaticVault{secret : sk}
        } else {
            log.Println("IDENTITYKIT_SECRET", err)
        }
    }

    var self = &FileVault{}
    return self
}

