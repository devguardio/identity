package main

import (
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/devguardio/identity/go"
	iktls "github.com/devguardio/identity/go/tls"
	"github.com/spf13/cobra"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

func tlsCmd() *cobra.Command {

	tlsCmd := &cobra.Command{
		Use:     "tls",
		Short:   "x509 mode",
		Aliases: []string{"x509"},
	}

	tlsCmd.AddCommand(&cobra.Command{
		Use:   "pem",
		Short: "export secret as PKCS8",
		Run: func(cmd *cobra.Command, args []string) {
			var vault = identity.Vault()
			if domain != "" {
				vault = vault.Domain(domain)
			}

			if usersa {
				p, err := vault.ExportRSASecret()
				if err != nil {
					panic(err)
				}
				pem, err := p.ToPem()
				if err != nil {
					panic(err)
				}
				os.Stdout.Write([]byte(pem))
			} else {
				p, err := vault.ExportSecret()
				if err != nil {
					panic(err)
				}
				pem, err := p.ToPem()
				if err != nil {
					panic(err)
				}
				os.Stdout.Write([]byte(pem))
			}
		},
	})

	tlsCmd.AddCommand(&cobra.Command{
		Use:   "ca",
		Short: "export public key as signed x509 cert",
		Run: func(cmd *cobra.Command, args []string) {
			var vault = identity.Vault()
			if domain != "" {
				vault = vault.Domain(domain)
			}

			if usersa {
				pub, err := vault.RSAPublic()
				if err != nil {
					panic(err)
				}

				cert, err := pub.ToCertificate()
				if err != nil {
					panic(err)
				}

				der, err := vault.SignRSACertificate(cert, pub)
				if err != nil {
					panic(err)
				}

				err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err != nil {
					panic(err)
				}
			} else {
				pub, err := vault.Identity()
				if err != nil {
					panic(err)
				}

				cert, err := pub.ToCertificate()
				if err != nil {
					panic(err)
				}

				der, err := vault.SignCertificate(cert, pub)
				if err != nil {
					panic(err)
				}

				err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err != nil {
					panic(err)
				}
			}
		},
	})

	var altips []string
	var altdns []string

	var cmdCert = &cobra.Command{
		Use:   "cert <subject>",
		Short: "create a new key/cert bundle, signed by the vault",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			var vault = identity.Vault()
			if domain != "" {
				vault = vault.Domain(domain)
			}

			var altipsi = make([]net.IP, len(altips))
			for i, _ := range altips {
				altipsi[i] = net.ParseIP(altips[i])
				if altipsi[i] == nil {
					panic("cannot parse --ip " + altips[i])
				}
			}

			var notBefore = time.Now().Add(-1 * time.Hour)
			var notAfter = notBefore.Add(time.Hour * 87600)

			cert := &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject: pkix.Name{
					Organization: []string{"identitykit"},
					CommonName:   args[0],
				},
				NotBefore:   notBefore,
				NotAfter:    notAfter,
				IsCA:        false,
				KeyUsage:    x509.KeyUsageDigitalSignature,
				ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
				DNSNames:    altdns,
				IPAddresses: altipsi,
			}

			if usersa {
				key, err := identity.CreateRSASecret(2048)
				if err != nil {
					panic(err)
				}

				pub := key.RSAPublic()

				der, err := vault.SignRSACertificate(cert, pub)
				if err != nil {
					panic(err)
				}

				err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err != nil {
					panic(err)
				}

				pem, err := key.ToPem()
				if err != nil {
					panic(err)
				}
				os.Stdout.Write([]byte(pem))

			} else {
				key, err := identity.CreateSecret()
				if err != nil {
					panic(err)
				}

				pub, err := key.Identity()
				if err != nil {
					panic(err)
				}
				cert.SubjectKeyId = pub[:]

				der, err := vault.SignCertificate(cert, pub)
				if err != nil {
					panic(err)
				}

				err = pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: der})
				if err != nil {
					panic(err)
				}

				pem, err := key.ToPem()
				if err != nil {
					panic(err)
				}
				os.Stdout.Write([]byte(pem))
			}
		},
	}

	cmdCert.Flags().StringSliceVar(&altips, "ip", []string{}, "Subject Alternate Name Ip Address")
	cmdCert.Flags().StringSliceVar(&altdns, "dns", []string{}, "Subject Alternate Name DNS Name")

	tlsCmd.AddCommand(cmdCert)

	tlsCmd.AddCommand(&cobra.Command{
		Use:   "serve",
		Short: "launch an https test server with a certificate bundle signed by the vault",
		Run: func(cmd *cobra.Command, args []string) {

			var vault = identity.Vault()

			pub, err := vault.Identity()
			if err != nil {
				panic(err)
			}

			cert, err := pub.ToCertificate()
			if err != nil {
				panic(err)
			}

			rootCert, err := vault.SignCertificate(cert, pub)
			if err != nil {
				panic(err)
			}

			if domain != "" {
				vault = vault.Domain(domain)
			}
			var tlsconfig = &tls.Config{
				InsecureSkipVerify: true,
				MaxVersion:         tls.VersionTLS12,
				GetCertificate: func(helo *tls.ClientHelloInfo) (*tls.Certificate, error) {

					log.Println("SNI: ", helo.ServerName)

					var notBefore = time.Now().Add(-1 * time.Hour)
					var notAfter = notBefore.Add(time.Hour * 87600)

					cert := &x509.Certificate{
						SerialNumber: big.NewInt(1),
						Subject: pkix.Name{
							Organization: []string{"identitykit"},
							CommonName:   helo.ServerName,
						},
						NotBefore:   notBefore,
						NotAfter:    notAfter,
						IsCA:        false,
						KeyUsage:    x509.KeyUsageDigitalSignature,
						ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
					}

					key, err := identity.CreateSecret()
					if err != nil {
						panic(err)
					}

					pub, err := key.Identity()
					if err != nil {
						panic(err)
					}
					cert.SubjectKeyId = pub[:]

					der, err := vault.SignCertificate(cert, pub)
					if err != nil {
						panic(err)
					}

					_ = rootCert

					return &tls.Certificate{
						PrivateKey:  key.ToGo(),
						Certificate: [][]byte{der, rootCert},
					}, nil
				},
				ClientAuth:            tls.RequireAnyClientCert,
				VerifyPeerCertificate: iktls.VerifyPeerCertificate,
			}

			server := http.Server{
				Addr: "0.0.0.0:8443",
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					id := iktls.ClaimedPeerIdentity(r.TLS)
					fmt.Fprintf(w, "Hello, %s\n", id.String())
				}),
				TLSConfig: tlsconfig,
			}
			log.Println("listening on 0.0.0.0:8443")
			err = server.ListenAndServeTLS("", "")
			if err != nil {
				panic(err)
			}
		},
	})

	var expected_server_identity string
	var headers []string
	var printHeaders bool = false

	var common = func(surl string) (*tls.Conn, error) {
		vault := identity.Vault()
		if domain != "" {
			vault = vault.Domain(domain)
		}
		tlsconf, err := iktls.NewTlsClient(vault)
		if err != nil {
			return nil, err
		}

		if expected_server_identity != "" {

			eid, err := identity.IdentityFromString(expected_server_identity)
			if err != nil {
				return nil, fmt.Errorf("--verify %s : %w", expected_server_identity, err)
			}

			tlsconf.VerifyPeerCertificate = iktls.VerifyPeerIdentity(eid)
			tlsconf.InsecureSkipVerify = true
		} else {
			tlsconf.VerifyPeerCertificate = iktls.VerifyPeerCertificate
			tlsconf.InsecureSkipVerify = true
		}

		u, err := url.Parse(surl)
		if err != nil {
			return nil, err
		}

		tlsconf.ServerName, _, _ = net.SplitHostPort(u.Host)

		dial, err := net.Dial("tcp", u.Host)
		if err != nil {
			return nil, err
		}

		tlsconn := tls.Client(dial, tlsconf)

		err = tlsconn.Handshake()
		if err != nil {
			return nil, err
		}

		if expected_server_identity != "" {
			cst := tlsconn.ConnectionState()
			id := iktls.ClaimedPeerIdentity(&cst)
			if id.String() != expected_server_identity {
				return nil, fmt.Errorf("cannot verify remote identity: it is %s instead of %s", id.String(), expected_server_identity)
			}
		}

		return tlsconn, nil
	}

	getCmd := &cobra.Command{
		Use:   "get <url>",
		Short: "https test client",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			client := &http.Client{
				Transport: &http.Transport{
					DialTLS: func(network, addr string) (net.Conn, error) {
						conn, err := common(args[0])
						if err != nil {
							panic(err)
						}
						return conn, nil
					},
				},
			}

			req, err := http.NewRequest("GET", args[0], nil)
			if err != nil {
				panic(err)
			}

			for _, v := range headers {
				v2 := strings.Split(v, ":")
				if len(v2) > 1 {
					req.Header.Add(v2[0], strings.Join(v2[1:], ":"))
				}
			}

			resp, err := client.Do(req)
			if err != nil {
				panic(err)
			}

			if printHeaders {
				fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
				for k, v := range resp.Header {
					for _, v := range v {
						fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
					}
				}
				fmt.Fprintf(os.Stderr, "\n")
			}

			io.Copy(os.Stdout, resp.Body)

			if resp.StatusCode >= 300 {
				if !printHeaders {
					fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
				}
				os.Exit(resp.StatusCode)
			}
		},
	}
	getCmd.Flags().BoolVarP(&printHeaders, "include", "i", false, "print headers to stderr")
	getCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "set request header")
	getCmd.Flags().StringVarP(&expected_server_identity, "verify", "e", "", "verify remote identity")
	tlsCmd.AddCommand(getCmd)

	conCmd := &cobra.Command{
		Use:   "connect <url>",
		Short: "test client connecting stdio to a remote stream",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {

			tlsconn, err := common(args[0])
			if err != nil {
				panic(err)
			}
			defer tlsconn.Close()

			conn := httputil.NewClientConn(tlsconn, nil)

			req, err := http.NewRequest("CONNECT", args[0], nil)
			if err != nil {
				panic(err)
			}

			for _, v := range headers {
				v2 := strings.Split(v, ":")
				if len(v2) > 1 {
					req.Header.Add(v2[0], strings.Join(v2[1:], ":"))
				}
			}

			resp, err := conn.Do(req)
			if err != nil {
				panic(err)
			}

			if printHeaders {
				fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
				for k, v := range resp.Header {
					for _, v := range v {
						fmt.Fprintf(os.Stderr, "%s: %s\n", k, v)
					}
				}
				fmt.Fprintf(os.Stderr, "\n")
			}

			if resp.StatusCode >= 300 {
				if !printHeaders {
					fmt.Fprintf(os.Stderr, "%s %s\n", resp.Proto, resp.Status)
				}
				io.Copy(os.Stderr, resp.Body)
				os.Exit(resp.StatusCode)
				return
			}

			connection, reader := conn.Hijack()
			go func() {
				defer connection.Close()
				io.Copy(connection, os.Stdin)

			}()
			io.Copy(os.Stdout, reader)

		},
	}

	conCmd.Flags().BoolVarP(&printHeaders, "include", "i", false, "print headers to stderr")
	conCmd.Flags().StringSliceVarP(&headers, "header", "H", []string{}, "set request header")
	conCmd.Flags().StringVarP(&expected_server_identity, "verify", "e", "", "verify remote identity")
	tlsCmd.AddCommand(conCmd)

	return tlsCmd
}
