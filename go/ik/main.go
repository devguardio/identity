package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "log"
    "fmt"
    "os"
    "encoding/pem"
    "crypto/x509"
    "math/big"
    "time"
    "crypto/x509/pkix"
    "net"
    "crypto/tls"
    "net/http"
    "io/ioutil"
)

func main() {
    log.SetFlags(log.Lshortfile);

    var rootCmd = cobra.Command{
        Use:        "identitykit",
        Short:      "\ncryptographic identity toolkit",
        Version:    "1",
    }

    var usersa = false
    rootCmd.PersistentFlags().BoolVarP(&usersa, "rsa", "r", false, "use rsa instead of ed25519")







    var mCmd = &cobra.Command{
        Use:        "msg",
        Aliases:    []string{"m"},
        Short:      "generic signed messages",
    }
    rootCmd.AddCommand(mCmd);

    mCmd.AddCommand(&cobra.Command{
        Use:        "sign <filename>",
        Short:      "sign a file and create a <filename>.iksig in the same directory",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {

            b, err := ioutil.ReadFile(args[0])
            if err != nil { panic(err) }

            sig, err := identity.Vault().Sign("iksig", b)
            if err != nil { panic(err) }

            f, err := os.OpenFile(args[0] + ".iksig", os.O_RDWR | os.O_CREATE | os.O_EXCL, 0755)
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }

            _, err = f.Write([]byte(sig.String() + "\n"))
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }
        },
    });

    var argIdentity string
    verifyCmd := &cobra.Command{
        Use:        "verify <filename> [ -I <identity> |  -A <anchor> ]",
        Short:      "verify a file is signed by an identity or anchor using <filename>.iksig in the same directory",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {


            if argIdentity == "" {
                panic("-I or -A required")
            }

            id, err := identity.IdentityFromString(argIdentity)
            if err != nil { panic(fmt.Errorf("%s : %w", argIdentity, err)) }

            b, err := ioutil.ReadFile(args[0])
            if err != nil { panic(fmt.Errorf("%s : %w", args[0], err)) }

            bs, err := ioutil.ReadFile(args[0] + ".iksig")
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }

            sig, err := identity.SignatureFromString(string(bs))
            if err != nil { panic(fmt.Errorf("%s : %w", args[0] + ".iksig", err)) }

            if sig.Verify("iksig", b, id) {
                fmt.Println("GOOD")
            } else {
                fmt.Println("BAD")
                os.Exit(2)
            }
        },
    };
    verifyCmd.Flags().StringVarP(&argIdentity, "identity", "I",  "", "public identity")
    mCmd.AddCommand(verifyCmd);



    compat := &cobra.Command{
        Use:        "convert <id>",
        Short:      "legacy conversion commands",
        Aliases:    []string{"cv", "conv"},
    }
    compat.AddCommand(&cobra.Command{
        Use:        "id32to58 <id>",
        Short:      "convert a b32 identity to a legacy b58",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            id, err := identity.IdentityFromString(args[0])
            if err != nil { panic(err) }
            fmt.Println(id.String58())
        },
    });
    rootCmd.AddCommand(compat);

    rootCmd.AddCommand(&cobra.Command{
        Use:        "identity ",
        Aliases:    []string{"id"},
        Short:      "print my identity",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                id, err := identity.Vault().RSAPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            } else {
                id, err := identity.Vault().Identity()
                if err != nil { panic(err) }
                fmt.Println(id)
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "address",
        Aliases:  []string{"xp", "addr"},
        Short:  "print my DH address",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                panic("rsa doesn't work with diffie-hellman")
            } else {
                id, err := identity.Vault().XPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "init",
        Short:  "initialize empty vault",
        Run: func(cmd *cobra.Command, args []string) {
            err := identity.Vault().Init(true)
            if err != nil { panic(err) }

            id, err := identity.Vault().Identity()
            if err != nil { panic(err) }
            fmt.Println(id)
        },
    });

    tlsCmd := &cobra.Command{
        Use:        "tls",
        Short:      "x509 mode",
        Aliases:    []string{"x509"},
    }
    rootCmd.AddCommand(tlsCmd);

    tlsCmd.AddCommand(&cobra.Command{
        Use:    "pem",
        Short:  "export secret as PKCS8",
        Run: func(cmd *cobra.Command, args []string) {
            if usersa {
                p, err := identity.Vault().ExportRSASecret()
                if err != nil { panic(err) }
                pem, err := p.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            } else {
                p, err := identity.Vault().ExportSecret()
                if err != nil { panic(err) }
                pem, err := p.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    });

    tlsCmd.AddCommand(&cobra.Command{
        Use:    "ca",
        Short:  "export public key as x509 cert",
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault();

            if usersa {
                pub, err := vault.RSAPublic();
                if err != nil { panic(err) }

                cert, err := pub.ToCertificate();
                if err != nil { panic(err) }

                der, err := vault.SignRSACertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }
            } else {
                pub, err := vault.Identity();
                if err != nil { panic(err) }

                cert, err := pub.ToCertificate();
                if err != nil { panic(err) }

                der, err := vault.SignCertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }
            }
        },
    });


    var altips []string
    var altdns []string

    var cmdCert = &cobra.Command{
        Use:    "cert <subject>",
        Short:  "create a new key/cert bundle, signed by the vault",
        Args:   cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault();

            var altipsi = make([]net.IP, len(altips))
            for i,_ := range(altips) {
                altipsi[i] = net.ParseIP(altips[i])
                if altipsi[i] == nil {
                    panic("cannot parse --ip " + altips[i]);
                }
            }

            var notBefore = time.Now().Add(-1 * time.Hour)
            var notAfter  = notBefore.Add(time.Hour * 87600)

            cert := &x509.Certificate{
                SerialNumber: big.NewInt(1),
                Subject: pkix.Name{
                    Organization:           []string{"identitykit"},
                    CommonName:             args[0],
                },
                NotBefore:              notBefore,
                NotAfter:               notAfter,
                IsCA:                   false,
                KeyUsage:               x509.KeyUsageDigitalSignature,
                ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                DNSNames:               altdns,
                IPAddresses:            altipsi,
            }

            if usersa {
                key, err := identity.CreateRSASecret(2048);
                if err != nil { panic(err) }

                pub := key.RSAPublic();

                der, err := vault.SignRSACertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }

                pem, err := key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))

            } else {
                key, err := identity.CreateSecret();
                if err != nil { panic(err) }

                pub,err := key.Identity();
                if err != nil { panic(err) }
                cert.SubjectKeyId = pub[:];

                der, err := vault.SignCertificate(cert, pub);
                if err != nil { panic(err) }

                err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der});
                if err != nil { panic(err) }

                pem, err := key.ToPem()
                if err != nil { panic(err) }
                os.Stdout.Write([]byte(pem))
            }
        },
    };

    cmdCert.Flags().StringSliceVar(&altips, "ip",  []string{}, "Subject Alternate Name Ip Address")
    cmdCert.Flags().StringSliceVar(&altdns, "dns", []string{}, "Subject Alternate Name DNS Name")

    tlsCmd.AddCommand(cmdCert);





    tlsCmd.AddCommand(&cobra.Command{
        Use:    "serve",
        Short:  "launch an https test server with a certificate bundle signed by the vault",
        Run: func(cmd *cobra.Command, args []string) {

            var vault = identity.Vault();
            var tlsconfig = &tls.Config{
                InsecureSkipVerify: true,
                MaxVersion:         tls.VersionTLS12,
                GetCertificate: func(helo*tls.ClientHelloInfo) (*tls.Certificate, error) {

                    log.Println("SNI: ", helo.ServerName);

                    var notBefore = time.Now().Add(-1 * time.Hour)
                    var notAfter  = notBefore.Add(time.Hour * 87600)

                    cert := &x509.Certificate{
                        SerialNumber: big.NewInt(1),
                        Subject: pkix.Name{
                            Organization:           []string{"identitykit"},
                            CommonName:             helo.ServerName,
                        },
                        NotBefore:              notBefore,
                        NotAfter:               notAfter,
                        IsCA:                   false,
                        KeyUsage:               x509.KeyUsageDigitalSignature,
                        ExtKeyUsage:            []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
                    }

                    key, err := identity.CreateSecret();
                    if err != nil { panic(err) }

                    pub, err := key.Identity();
                    if err != nil { panic(err) }
                    cert.SubjectKeyId = pub[:];

                    der, err := vault.SignCertificate(cert, pub);
                    if err != nil { panic(err) }

                    return &tls.Certificate{
                        PrivateKey: key.ToGo(),
                        Certificate: [][]byte{der},
                    }, nil
                },
                ClientAuth: tls.RequireAnyClientCert,
                VerifyPeerCertificate: identity.VerifyPeerCertificate,
            };

            server := http.Server{
                Addr:      "0.0.0.0:8443",
                Handler:   http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                    id := identity.ClaimedPeerIdentity(r.TLS);
                    fmt.Fprintf(w, "Hello, %s\n", id.String())
                }),
                TLSConfig: tlsconfig,
            }
            log.Println("listening on 0.0.0.0:8443");
            err := server.ListenAndServeTLS("", "")
            if err != nil { panic(err) }
        },
    });

    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}