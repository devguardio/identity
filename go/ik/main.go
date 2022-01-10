package main

import (
    "github.com/spf13/cobra"
    "github.com/devguardio/identity/go"
    "log"
    "fmt"
    "os"
    "encoding/hex"
)

var usersa = false
var domain = ""

func main() {
    log.SetFlags(log.Lshortfile);

    var rootCmd = cobra.Command{
        Use:        "identitykit",
        Short:      "\ncryptographic identity toolkit",
        Version:    "1",
    }

    rootCmd.AddCommand(tlsCmd())

    compat := &cobra.Command{
        Use:        "convert <id>",
        Short:      "conversion commands",
        Aliases:    []string{"cv", "conv"},
    }
    compat.AddCommand(&cobra.Command{
        Use:        "hex2secret <hex>",
        Short:      "convert a hex encoded secret seed to an ik secret",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            decoded, err := hex.DecodeString(args[0])
            if err != nil { panic(err) }
            if len(decoded) < 32 {panic("must be at least 32 bytes long")}
            var sk identity.Secret
            copy(sk[:], decoded[:32])
            fmt.Println(sk.ToString())
        },
    });
    compat.AddCommand(&cobra.Command{
        Use:        "hex2identity <hex>",
        Short:      "convert a hex encoded public key seed to an ik identity",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            decoded, err := hex.DecodeString(args[0])
            if err != nil { panic(err) }
            if len(decoded) < 32 {panic("must be at least 32 bytes long")}
            var sk identity.Identity
            copy(sk[:], decoded[:32])
            fmt.Println(sk.String())
        },
    });
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
    compat.AddCommand(&cobra.Command{
        Use:        "secret2public <Secret>",
        Short:      "convert a secret to an identity",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            s, err := identity.SecretFromString(args[0])
            if err != nil { panic(err) }
            id, err := s.Identity();
            if err != nil { panic(err) }
            fmt.Println(id.String())
        },
    });
    compat.AddCommand(&cobra.Command{
        Use:        "secret2address <Secret>",
        Short:      "convert a secret to an address",
        Args:       cobra.MinimumNArgs(1),
        Run: func(cmd *cobra.Command, args []string) {
            s, err := identity.SecretFromString(args[0])
            if err != nil { panic(err) }
            xs := s.XSecret();
            if err != nil { panic(err) }
            fmt.Println(xs.XPublic().String())
        },
    });
    rootCmd.AddCommand(compat);

    rootCmd.PersistentFlags().BoolVarP(&usersa, "rsa", "r", false, "use rsa instead of ed25519")
    rootCmd.PersistentFlags().StringVarP(&domain, "domain", "u", "", "use vault in separate user specific domain")

    rootCmd.AddCommand(&cobra.Command{
        Use:        "identity ",
        Aliases:    []string{"id"},
        Short:      "print my identity",
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault()
            if domain != "" { vault = vault.Domain(domain) }

            if usersa {
                id, err := vault.RSAPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            } else {
                id, err := vault.Identity()
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
            var vault = identity.Vault()
            if domain != "" { vault = vault.Domain(domain) }

            if usersa {
                panic("rsa doesn't work with diffie-hellman")
            } else {
                id, err := vault.XPublic()
                if err != nil { panic(err) }
                fmt.Println(id)
            }
        },
    });

    rootCmd.AddCommand(&cobra.Command{
        Use:    "init",
        Short:  "initialize empty vault",
        Run: func(cmd *cobra.Command, args []string) {
            var vault = identity.Vault()
            if domain != "" { vault = vault.Domain(domain) }

            err := vault.Init(true)
            if err != nil { panic(err) }

            id, err := vault.Identity()
            if err != nil { panic(err) }
            fmt.Println(id)
        },
    });


    if err := rootCmd.Execute(); err != nil {
        os.Exit(1);
    }
}
