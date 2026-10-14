package middleware

import (
	"errors"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/gin-gonic/gin"
)

// LinkTransport checks the actual peer rather than Gin's forwarded client address.
func LinkTransport() gin.HandlerFunc {
	insecureTestOrigin := common.LinkInsecureTestOrigin()
	trustedProxies, defaults, err := common.ResolveTrustedProxies(os.Getenv("TRUSTED_PROXIES"))
	if defaults {
		// Sensitive desktop credentials do not inherit the gateway's broad
		// private-network compatibility defaults. Container proxies must be explicit.
		trustedProxies = []string{"127.0.0.0/8", "::1"}
	}
	var trustedNetworks []*net.IPNet
	if err == nil {
		for _, proxy := range trustedProxies {
			if ip := net.ParseIP(proxy); ip != nil {
				bits := 128
				if ip.To4() != nil {
					bits = 32
				}
				trustedNetworks = append(trustedNetworks, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
				continue
			}
			_, network, parseErr := net.ParseCIDR(proxy)
			if parseErr != nil {
				trustedNetworks = nil
				break
			}
			trustedNetworks = append(trustedNetworks, network)
		}
	}
	return func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("Pragma", "no-cache")
		c.Header("Referrer-Policy", "no-referrer")
		peer, _, err := net.SplitHostPort(c.Request.RemoteAddr)
		if err != nil {
			peer = c.Request.RemoteAddr
		}
		ip := net.ParseIP(peer)
		local := ip != nil && ip.IsLoopback()
		host := c.Request.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		hostIP := net.ParseIP(strings.Trim(host, "[]"))
		localHost := host == "localhost" || (hostIP != nil && hostIP.IsLoopback())
		forwarded := c.Request.Header.Values("X-Forwarded-Proto")
		trustedTLS := len(forwarded) == 1 && forwarded[0] == "https" && slices.ContainsFunc(trustedNetworks, func(network *net.IPNet) bool {
			return network.Contains(ip)
		})
		// This opt-in exception uses the actual Host, never forwarded host or
		// protocol headers. It is intentionally restricted to one test origin.
		insecureTestRequest := false
		if insecureTestOrigin != "" && !strings.ContainsAny(c.Request.Host, "/?#@") && !strings.HasSuffix(c.Request.Host, ":") {
			requestOrigin, err := common.NormalizeOrigin("http://" + c.Request.Host)
			insecureTestRequest = err == nil && requestOrigin == insecureTestOrigin
		}
		if c.Request.TLS == nil && !(local && localHost) && !trustedTLS && !insecureTestRequest {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"success": false, "code": "LINK_TLS_REQUIRED", "message": "HTTPS is required", "message_key": "HTTPS is required"})
			return
		}
		c.Next()
	}
}
func LinkAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		raw, ok := strings.CutPrefix(c.GetHeader("Authorization"), "Bearer ")
		if !ok {
			writeLinkAuthFailure(c, model.ErrLinkUnauthorized)
			return
		}
		session, err := model.ValidateLinkSession(raw)
		if err != nil {
			writeLinkAuthFailure(c, err)
			return
		}
		c.Set("link_session", session)
		c.Set("id", session.UserID)
		c.Next()
	}
}
func GetLinkSession(c *gin.Context) *model.LinkSession {
	value, _ := c.Get("link_session")
	s, _ := value.(*model.LinkSession)
	return s
}
func writeLinkAuthFailure(c *gin.Context, err error) {
	var failure *model.LinkError
	if !errors.As(err, &failure) {
		failure = &model.LinkError{Status: 500, Code: "LINK_INTERNAL_ERROR", Message: "Client authentication unavailable"}
	}
	message := common.NewMessage(failure.Message)
	fields := message.Fields()
	fields["success"], fields["code"], fields["message"] = false, failure.Code, message.Error()
	c.AbortWithStatusJSON(failure.Status, fields)
}

// LinkBrowserPrivacy also covers the first HTML navigation, before any JavaScript runs.
func LinkBrowserPrivacy() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.URL.Path == "/link/authorize" || c.Request.URL.Path == "/sign-in" {
			c.Header("Referrer-Policy", "no-referrer")
			c.Header("Cache-Control", "no-store")
			c.Header("Pragma", "no-cache")
		}
		c.Next()
	}
}
