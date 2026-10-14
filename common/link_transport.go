package common

import (
	"net/url"
	"os"
	"strconv"
	"strings"
)

// LinkInsecureTestOrigin returns the one explicitly configured plaintext test
// origin, or an empty string when disabled or misconfigured. It never changes
// the gateway's session cookie or trusted proxy settings.
func LinkInsecureTestOrigin() string {
	var testOrigin string
	for _, key := range []string{"LINK_INSECURE_TEST_ORIGIN", "LINK_PUBLIC_URL"} {
		raw := strings.TrimSpace(os.Getenv(key))
		u, err := url.Parse(raw)
		if err != nil || u.Scheme != "http" || u.RawPath != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.HasSuffix(u.Host, ":") {
			return ""
		}
		origin, err := NormalizeOrigin(raw)
		if err != nil {
			return ""
		}
		if port := u.Port(); port != "" {
			value, err := strconv.Atoi(port)
			if err != nil || value < 1 || value > 65535 {
				return ""
			}
		}
		if testOrigin == "" {
			testOrigin = origin
		} else if testOrigin != origin {
			return ""
		}
	}
	return testOrigin
}
