//go:build openwrt

package identity

import (
	"os"
)

func DefaultPath(domain string) string {
	var path = "/etc/config/identitykit"
	os.MkdirAll(path, os.ModePerm)
	return path
}
