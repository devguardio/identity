//go:build android

package identity

import (
    "os"
)

func DefaultPath(domain string) string {
    var path = "/data/identitykit"
    os.MkdirAll(path, os.ModePerm)
    return path;
}

