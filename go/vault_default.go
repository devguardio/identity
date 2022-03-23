//go:build (!android && !openwrt)

package identity

import (
    "os"
)

func DefaultPath(domain string) string {
    var path = os.Getenv("IDENTITYKIT_PATH")
    var err error

    if path == "" {
        path, err = os.UserHomeDir()
        if err != nil  || path == "" {
            path = "/root/"
        }
        path += "/.identitykit"
    }

    if domain != "" {
        path += "/" + domain
    }

    os.MkdirAll(path, os.ModePerm)

    return path;
}

