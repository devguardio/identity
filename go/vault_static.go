package identity

import (
	"crypto/rand"
	"crypto/x509"
	"errors"
)

var RSAError = errors.New("IDENTITYKIT_SECRET environment variable is incompatible with rsa secrets")

func (self *Secret) Domain(domain string) VaultI {
	return self
}

func (self *Secret) Init(interactive bool) error {
	return nil
}

func (self *Secret) XPublic() (*XPublic, error) {
	return self.XSecret().XPublic(), nil
}

func (self *Secret) RSAPublic() (*RSAPublic, error) {
	return nil, RSAError
}

func (self *Secret) ExportSecret() (*Secret, error) {
	return self, nil
}

func (self *Secret) ExportRSASecret() (*RSASecret, error) {
	return nil, RSAError
}

func (self *Secret) SignCertificate(template *x509.Certificate, pub *Identity) ([]byte, error) {
	pk, err := self.Identity()
	if err != nil {
		return nil, err
	}

	parent, err := pk.ToCertificate()
	if err != nil {
		return nil, err
	}

	return x509.CreateCertificate(rand.Reader, template, parent, pub.ToGo(), self.ToGo())
}

func (self *Secret) SignRSACertificate(template *x509.Certificate, pub *RSAPublic) ([]byte, error) {
	return nil, RSAError
}
