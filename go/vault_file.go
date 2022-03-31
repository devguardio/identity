package identity

import (
    "io/ioutil"
    "os"
    "errors"
    "log"
    "crypto/x509"
    "crypto/rand"
    "regexp"
)

type FileVault struct {
    domain string
}

func (self *FileVault) Domain(domain string) VaultI {

    reg, err := regexp.Compile("[^a-zA-Z0-9]+")
    if err != nil { panic(err) }
    domain = reg.ReplaceAllString(domain, "_")

    return &FileVault{domain:domain}
}

func (self *FileVault) Init(interactive bool)  error {

    var path = DefaultPath(self.domain);

    var path2 = path + "/ed25519.secret"
    if _, err := os.Stat(path2); !os.IsNotExist(err) {
        if interactive {
            log.Println("NOT overriding existing ", path2)
        }
    } else {

        secret, err := CreateSecret()
        if err != nil { return err}

        err = ioutil.WriteFile(path2, []byte(secret.ToString()), 0400)
        if err != nil { return err}
    }


    path2 = path + "/rsa.secret"
    if _, err := os.Stat(path2); !os.IsNotExist(err) {
        if interactive {
            log.Println("NOT overriding existing ", path2)
        }
    } else {

        secret, err := CreateRSASecret(3072)
        if err != nil { return err}

        err = ioutil.WriteFile(path2, []byte(secret.ToString()), 0400)
        if err != nil { return err}
    }


    return nil
}

func (self *FileVault) Secret()  (*Secret, error) {
    var path = DefaultPath(self.domain) + "/ed25519.secret"

    if _, err := os.Stat(path); os.IsNotExist(err) {
        if self.domain != "" {
            return nil, errors.New("missing " + path + "\n=> run 'ik init --domain " + self.domain + "' to create a new identity")
        } else {
            return nil, errors.New("missing " + path + "\n=> run 'ik init' to create a new identity")
        }
    }

    content, err := ioutil.ReadFile(path)
    if err != nil { return nil, err}

    s, err := SecretFromString(string(content))
    if err != nil { return nil, err}

    return s, nil
}

func (self *FileVault) RSASecret()  (*RSASecret, error) {
    var path = DefaultPath(self.domain) + "/rsa.secret"

    if _, err := os.Stat(path); os.IsNotExist(err) {
        if self.domain != "" {
            return nil, errors.New("missing " + path + "\n=> run 'ik init --domain " + self.domain + "' to create a new identity")
        } else {
            return nil, errors.New("missing " + path + "\n=> run 'ik init' to create a new identity")
        }
    }

    content, err := ioutil.ReadFile(path)
    if err != nil { return nil, err}

    s, err := RSASecretFromString(string(content))
    if err != nil { return nil, err}

    return s, nil
}

func (self *FileVault) Identity()  (*Identity, error) {
    secret, err := self.Secret()
    if err != nil { return nil, err}
    return secret.Identity()
}

func (self *FileVault) XPublic()  (*XPublic, error) {
    secret, err := self.Secret()
    if err != nil { return nil, err}
    return secret.XSecret().XPublic(), nil
}

func (self *FileVault) RSAPublic()  (*RSAPublic, error) {
    secret, err := self.RSASecret()
    if err != nil { return nil, err}
    return secret.RSAPublic(), nil
}

func (self *FileVault) ExportSecret() (*Secret, error) {
    return self.Secret()
}

func (self *FileVault) ExportRSASecret() (*RSASecret, error) {
    return self.RSASecret()
}

func (self *FileVault) SignCertificate (template * x509.Certificate, pub *Identity) ([]byte, error) {
    k, err := self.Secret()
    if err != nil { return nil, err }

    pk, err := k.Identity()
    if err != nil { return nil, err }

    parent, err := pk.ToCertificate();
    if err != nil { return nil, err }

    return x509.CreateCertificate(rand.Reader, template, parent, pub.ToGo(), k.ToGo())
}

func (self *FileVault) SignRSACertificate (template * x509.Certificate, pub *RSAPublic) ([]byte, error) {
    k, err := self.RSASecret()
    if err != nil { return nil, err }

    parent, err := k.RSAPublic().ToCertificate();
    if err != nil { return nil, err }

    return x509.CreateCertificate(rand.Reader, template, parent, pub.ToGo(), k.ToGo())
}

func (self *FileVault) Sign(subject string, message []byte) (*Signature, error) {
    k, err := self.Secret()
    if err != nil { return nil, err }
    return k.Sign(subject, message)
}
