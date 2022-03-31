package identity

import (
    "crypto/x509"
    "crypto/rand"
    "errors"
)

var RSAError = errors.New("IDENTITYKIT_SECRET environment variable is incompatible with rsa secrets")

type StaticVault struct {
    secret *Secret
}

func (self *StaticVault) Domain(domain string) VaultI {
    return self
}

func (self *StaticVault) Init(interactive bool)  error {
    return nil
}

func (self *StaticVault) Identity()  (*Identity, error) {
    return self.secret.Identity()
}

func (self *StaticVault) XPublic()  (*XPublic, error) {
    return self.secret.XSecret().XPublic(), nil
}

func (self *StaticVault) RSAPublic()  (*RSAPublic, error) {
    return nil, RSAError
}

func (self *StaticVault) ExportSecret() (*Secret, error) {
    return self.secret, nil
}

func (self *StaticVault) ExportRSASecret() (*RSASecret, error) {
    return nil, RSAError
}

func (self *StaticVault) SignCertificate (template * x509.Certificate, pub *Identity) ([]byte, error) {
    pk, err := self.secret.Identity()
    if err != nil { return nil, err }

    parent, err := pk.ToCertificate();
    if err != nil { return nil, err }

    return x509.CreateCertificate(rand.Reader, template, parent, pub.ToGo(), self.secret.ToGo())
}

func (self *StaticVault) SignRSACertificate (template * x509.Certificate, pub *RSAPublic) ([]byte, error) {
    return nil, RSAError
}

func (self *StaticVault) Sign(subject string, message []byte) (*Signature, error) {
    return self.secret.Sign(subject, message)
}
